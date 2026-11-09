use std::{
    fmt,
    io::ErrorKind,
    num::{NonZeroU32, NonZeroU64},
    os::unix::fs::{FileTypeExt, PermissionsExt},
    time::Duration,
};

use anyhow::{Context, bail};
use aya::{
    Ebpf,
    maps::{Array, HashMap, MapData},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use syn_flood_detect_common::{
    FirewallConfig, MODE_ALLOW, MODE_BLOCK, MODE_FILTER, UBF_ENTRIES, UpdatableBloomFilter,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

const SOCKET_PATH: &str = "/run/syn-flood-detect.sock";
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MESSAGE_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Allow,
    Block,
    Filter,
}

impl Mode {
    pub fn value(self) -> u32 {
        match self {
            Self::Allow => MODE_ALLOW,
            Self::Block => MODE_BLOCK,
            Self::Filter => MODE_FILTER,
        }
    }
}

impl TryFrom<u32> for Mode {
    type Error = anyhow::Error;
    fn try_from(value: u32) -> anyhow::Result<Self> {
        match value {
            MODE_ALLOW => Ok(Self::Allow),
            MODE_BLOCK => Ok(Self::Block),
            MODE_FILTER => Ok(Self::Filter),
            _ => bail!("invalid firewall mode: {value}"),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Filter => "filter",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Fnv1a,
    Murmur3,
    #[default]
    Halfsiphash,
}

impl HashAlgorithm {
    pub fn value(self) -> u32 {
        use syn_flood_detect_common::hashing::*;
        match self {
            Self::Fnv1a => HASH_FNV1A,
            Self::Murmur3 => HASH_MURMUR3,
            Self::Halfsiphash => HASH_HALFSIPHASH,
        }
    }
}

impl TryFrom<u32> for HashAlgorithm {
    type Error = anyhow::Error;
    fn try_from(value: u32) -> anyhow::Result<Self> {
        use syn_flood_detect_common::hashing::*;
        match value {
            HASH_FNV1A => Ok(Self::Fnv1a),
            HASH_MURMUR3 => Ok(Self::Murmur3),
            HASH_HALFSIPHASH => Ok(Self::Halfsiphash),
            _ => bail!("invalid hash algorithm: {value}"),
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            Self::Fnv1a => "fnv1a",
            Self::Murmur3 => "murmur3",
            Self::Halfsiphash => "halfsiphash",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    #[serde(rename = "mode")]
    packet_handling_mode: Mode,
    epoch_time_ms: u64,
    syn_count_block_threshold: u32,
    ubf_size: u32,
    hash_algorithm: HashAlgorithm,
}

impl TryFrom<FirewallConfig> for Configuration {
    type Error = anyhow::Error;
    fn try_from(config: FirewallConfig) -> anyhow::Result<Self> {
        if config.epoch_time_ms == 0 || config.syn_count_block_threshold == 0 {
            bail!("detector parameters must be positive");
        }
        if !(1..=UBF_ENTRIES).contains(&config.ubf_size) {
            bail!("ubf_size must be between 1 and {UBF_ENTRIES}");
        }
        Ok(Self {
            packet_handling_mode: config.packet_handling_mode.try_into()?,
            epoch_time_ms: config.epoch_time_ms,
            syn_count_block_threshold: config.syn_count_block_threshold,
            ubf_size: config.ubf_size,
            hash_algorithm: config.hash_algorithm.try_into()?,
        })
    }
}

impl From<Configuration> for FirewallConfig {
    fn from(config: Configuration) -> Self {
        Self {
            packet_handling_mode: config.packet_handling_mode.value(),
            hash_algorithm: config.hash_algorithm.value(),
            epoch_time_ms: config.epoch_time_ms,
            syn_count_block_threshold: config.syn_count_block_threshold,
            ubf_size: config.ubf_size,
        }
    }
}

impl fmt::Display for Configuration {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "mode={} epoch_time_ms={} syn_count_block_threshold={} ubf_size={} hash_algorithm={}",
            self.packet_handling_mode,
            self.epoch_time_ms,
            self.syn_count_block_threshold,
            self.ubf_size,
            self.hash_algorithm
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigUpdate {
    pub epoch_time_ms: Option<NonZeroU64>,
    pub syn_count_block_threshold: Option<NonZeroU32>,
    pub ubf_size: Option<u32>,
    pub hash_algorithm: Option<HashAlgorithm>,
}

impl ConfigUpdate {
    fn apply(self, mut current: Configuration) -> anyhow::Result<Configuration> {
        if self.epoch_time_ms.is_none()
            && self.syn_count_block_threshold.is_none()
            && self.ubf_size.is_none()
            && self.hash_algorithm.is_none()
        {
            bail!(
                "provide epoch_time_ms, syn_count_block_threshold, ubf_size and/or hash_algorithm"
            );
        }
        if let Some(value) = self.epoch_time_ms {
            current.epoch_time_ms = value.get();
        }
        if let Some(value) = self.syn_count_block_threshold {
            current.syn_count_block_threshold = value.get();
        }
        if let Some(value) = self.hash_algorithm {
            current.hash_algorithm = value;
        }
        if let Some(value) = self.ubf_size {
            current.ubf_size = value;
        }
        Configuration::try_from(FirewallConfig::from(current))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Mode {
        #[serde(rename = "mode")]
        packet_handling_mode: Mode,
    },
    Config(ConfigUpdate),
    Show {},
    Reset {},
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Ok { config: Configuration },
    Error { message: String },
}

impl From<anyhow::Result<Configuration>> for Response {
    fn from(result: anyhow::Result<Configuration>) -> Self {
        match result {
            Ok(config) => Self::Ok { config },
            Err(error) => Self::Error {
                message: format!("{error:#}"),
            },
        }
    }
}

// One JSON object per line, bounded before deserialization.
async fn read_message<T: DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
) -> anyhow::Result<T> {
    let mut bytes = Vec::new();
    for _ in 0..MAX_MESSAGE_BYTES {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            return serde_json::from_slice(&bytes).context("invalid control message");
        }
        bytes.push(byte);
    }
    bail!("control message exceeds 8 KiB including newline")
}

async fn write_message(
    stream: &mut (impl AsyncWrite + Unpin),
    message: &impl Serialize,
) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec(message)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_MESSAGE_BYTES {
        bail!("control message exceeds 8 KiB including newline");
    }
    stream.write_all(&bytes).await?;
    Ok(())
}

pub async fn send(request: Request) -> anyhow::Result<()> {
    let config = timeout(TIMEOUT, exchange(&request))
        .await
        .context("control request timed out; use show to check the current configuration")??;
    if matches!(request, Request::Reset {}) {
        println!("Detector history cleared; concurrent traffic may already have added new counts.");
    }
    println!("Firewall: {config}");
    Ok(())
}

async fn exchange(request: &Request) -> anyhow::Result<Configuration> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .await
        .context("firewall control unavailable; start it with run first")?;
    write_message(&mut stream, request).await?;
    match read_message(&mut stream).await? {
        Response::Ok { config } => Ok(config),
        Response::Error { message } => bail!("firewall rejected request: {message}"),
    }
}

pub struct ControlSocket(UnixListener);

impl ControlSocket {
    pub fn bind() -> anyhow::Result<Self> {
        remove_stale_socket()?;
        let socket = Self(UnixListener::bind(SOCKET_PATH)?);
        std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o600))?;
        Ok(socket)
    }
}

fn remove_stale_socket() -> anyhow::Result<()> {
    match std::fs::symlink_metadata(SOCKET_PATH) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            match std::os::unix::net::UnixStream::connect(SOCKET_PATH) {
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(SOCKET_PATH)?
                }
                _ => bail!("firewall control socket already in use"),
            }
        }
        Ok(_) => bail!("control socket path exists and is not a socket"),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(SOCKET_PATH);
    }
}

pub struct Controller {
    current: Configuration,
    config: HashMap<MapData, u32, FirewallConfig>,
    history: Array<MapData, UpdatableBloomFilter>,
}

impl Controller {
    pub fn new(ebpf: &mut Ebpf, initial: FirewallConfig) -> anyhow::Result<Self> {
        let current = Configuration::try_from(initial)?;
        let mut config = HashMap::try_from(
            ebpf.take_map("FIREWALL_CONFIG")
                .context("missing configuration map")?,
        )?;
        let history = Array::try_from(ebpf.take_map("UBF_ARRAY").context("missing detector map")?)?;
        config.insert(0, initial, 0)?;
        Ok(Self {
            current,
            config,
            history,
        })
    }

    pub fn snapshot(&self) -> Configuration {
        self.current
    }

    fn commit(&mut self, next: Configuration) -> anyhow::Result<()> {
        // Replace the complete value atomically for packet processing.
        self.config
            .insert(0, FirewallConfig::from(next), 0)
            .context("could not update configuration")?;
        self.current = next;
        Ok(())
    }

    fn change_mode(&mut self, packet_handling_mode: Mode) -> anyhow::Result<()> {
        if self.current.packet_handling_mode == packet_handling_mode {
            return Ok(());
        }
        if packet_handling_mode == Mode::Filter {
            self.clear_history()?;
        }
        self.commit(Configuration {
            packet_handling_mode,
            ..self.current
        })
    }

    fn clear_history(&mut self) -> anyhow::Result<()> {
        // Explicit reset leaves the current mode active: writes may race with eBPF.
        for index in 0..self.history.len() {
            self.history.set(index, UpdatableBloomFilter::default(), 0)
                .with_context(|| format!("history reset failed at index {index}; history may be partially cleared; configuration unchanged"))?;
        }
        Ok(())
    }

    fn handle(&mut self, request: Request) -> anyhow::Result<Configuration> {
        match request {
            Request::Mode {
                packet_handling_mode,
            } => self.change_mode(packet_handling_mode)?,
            Request::Config(update) => {
                let next = update.apply(self.current)?;
                if next.ubf_size != self.current.ubf_size
                    || next.hash_algorithm != self.current.hash_algorithm
                {
                    // Hash indices change. Quiesce traffic for a clean experimental boundary.
                    self.clear_history()?;
                }
                self.commit(next)?;
            }
            Request::Show {} => return Ok(self.snapshot()),
            Request::Reset {} => self.clear_history()?,
        }
        log::info!("control request applied: {}", self.current);
        Ok(self.snapshot())
    }

    async fn serve_connection(&mut self, stream: &mut UnixStream) -> anyhow::Result<()> {
        let result = match read_message::<Request>(stream).await {
            Ok(request) => self.handle(request),
            Err(error) => Err(error),
        };
        write_message(stream, &Response::from(result)).await
    }

    pub async fn serve(&mut self, socket: &ControlSocket) -> anyhow::Result<()> {
        loop {
            let (mut stream, _) = socket.0.accept().await?;
            match timeout(TIMEOUT, self.serve_connection(&mut stream)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("control request failed: {error:#}"),
                Err(_) => log::warn!("control request timed out"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_updates_preserve_other_parameters() {
        let initial = Configuration::try_from(FirewallConfig::default()).unwrap();
        assert_eq!(initial.hash_algorithm, HashAlgorithm::Halfsiphash);
        for name in ["fnv1a", "murmur3", "halfsiphash"] {
            let request = format!(r#"{{"command":"config","hash_algorithm":"{name}"}}"#);
            let Request::Config(update) = serde_json::from_str(&request).unwrap() else {
                panic!()
            };
            let changed = update.apply(initial).unwrap();
            assert_eq!(changed.hash_algorithm.to_string(), name);
            assert_eq!(changed.ubf_size, initial.ubf_size);
            assert_eq!(changed.epoch_time_ms, initial.epoch_time_ms);
            assert_eq!(changed.packet_handling_mode, initial.packet_handling_mode);
            assert_eq!(
                changed.syn_count_block_threshold,
                initial.syn_count_block_threshold
            );
            let update: ConfigUpdate = serde_json::from_str(r#"{"ubf_size":512}"#).unwrap();
            assert_eq!(
                update.apply(changed).unwrap().hash_algorithm,
                changed.hash_algorithm
            );
        }
        assert!(
            serde_json::from_str::<Request>(r#"{"command":"config","hash_algorithm":"invalid"}"#)
                .is_err()
        );
        assert!(
            Configuration::try_from(FirewallConfig {
                hash_algorithm: 99,
                ..FirewallConfig::default()
            })
            .is_err()
        );
        assert_eq!(core::mem::size_of::<FirewallConfig>(), 24);
    }

    #[test]
    #[ignore = "requires Linux BPF privileges; run in an isolated privileged container"]
    fn kernel_hash_transitions() {
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/syn-flood-detect"
        )))
        .unwrap();
        let program: &mut aya::programs::Xdp = ebpf
            .program_mut("syn_flood_detect")
            .unwrap()
            .try_into()
            .unwrap();
        program.load().unwrap(); // Includes verifier validation of all hash branches.
        let mut controller = Controller::new(&mut ebpf, FirewallConfig::default()).unwrap();
        for algorithm in [
            HashAlgorithm::Fnv1a,
            HashAlgorithm::Murmur3,
            HashAlgorithm::Halfsiphash,
        ] {
            controller
                .history
                .set(
                    0,
                    UpdatableBloomFilter {
                        counter: 7,
                        timestamp: 1,
                    },
                    0,
                )
                .unwrap();
            let update = ConfigUpdate {
                epoch_time_ms: None,
                syn_count_block_threshold: None,
                ubf_size: None,
                hash_algorithm: Some(algorithm),
            };
            controller.handle(Request::Config(update)).unwrap();
            assert_eq!(controller.history.get(&0, 0).unwrap().counter, 0);
            assert_eq!(
                controller.config.get(&0, 0).unwrap().hash_algorithm,
                algorithm.value()
            );
            use aya::programs::{TestRun, TestRunOptions, Xdp};
            use syn_flood_detect_common::hashing::*;
            let program: &mut Xdp = ebpf
                .program_mut("syn_flood_detect")
                .unwrap()
                .try_into()
                .unwrap();
            let mut packet = [0u8; 54];
            packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            packet[14] = 0x45;
            packet[16..18].copy_from_slice(&40u16.to_be_bytes());
            packet[23] = 6;
            packet[26..30].copy_from_slice(&[104, 0, 1, 1]);
            packet[30..34].copy_from_slice(&[203, 0, 113, 2]);
            packet[36..38].copy_from_slice(&80u16.to_be_bytes());
            packet[46] = 0x50;
            packet[47] = 2;
            let key = service_key([104, 0, 1, 1], [203, 0, 113, 2], 80);
            let hash = match algorithm {
                HashAlgorithm::Fnv1a => fnv1a_32(&key),
                HashAlgorithm::Murmur3 => murmur3_x86_32(&key),
                HashAlgorithm::Halfsiphash => halfsiphash_2_4_32(&key),
            };
            let index = hash % controller.current.ubf_size;
            let run = |bytes: &[u8]| {
                program
                    .test_run(TestRunOptions {
                        data_in: Some(bytes),
                        ..Default::default()
                    })
                    .unwrap()
                    .return_value
            };
            assert_eq!(run(&packet), 2); // XDP_PASS for the first SYN
            assert_eq!(controller.history.get(&index, 0).unwrap().counter, 1);
            packet[47] = 0x10;
            assert_eq!(run(&packet), 2); // ACK clears that same bucket
            assert_eq!(controller.history.get(&index, 0).unwrap().counter, 0);
            packet[47] = 2;
            assert_eq!(run(&packet), 2);
            assert_eq!(run(&packet), 2);
            assert_eq!(run(&packet), 1); // Third SYN reaches the default threshold

            controller
                .history
                .set(
                    0,
                    UpdatableBloomFilter {
                        counter: 7,
                        timestamp: 1,
                    },
                    0,
                )
                .unwrap();
            controller.handle(Request::Config(update)).unwrap();
            assert_eq!(controller.history.get(&0, 0).unwrap().counter, 7);
        }
    }
}
