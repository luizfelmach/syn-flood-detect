use anyhow::{Context, bail};
use aya::{
    Ebpf,
    maps::{MapData, PerCpuArray, RingBuf},
};
use csv::{Writer, WriterBuilder};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    net::Ipv4Addr,
    os::fd::AsRawFd,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use syn_flood_detect_common::*;
use tokio::task::JoinHandle;

const BATCH_SIZE: usize = 4096;
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const PACKET_HEADER: &str = "timestamp_monotonic_ns,ifindex,length_bytes,ethertype,src_ip,dst_ip,ip_protocol,src_port,dst_port,tcp_flags,mode,action";
const STATS_HEADER: &str =
    "timestamp_monotonic_ns,passed,dropped,aborted,events_lost,records_written";

pub struct Collector {
    ring: RingBuf<MapData>,
    stats: PerCpuArray<MapData, PacketStats>,
    packets: Writer<File>,
    totals: Writer<File>,
    written: u64,
}

// The handle is removed only after completion, so cancellation of wait is safe.
pub struct Worker {
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}

impl Worker {
    pub async fn wait(&mut self) -> anyhow::Result<()> {
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let result = task.await;
        self.task = None;
        result
            .context("join packet collector")?
            .context("packet collector failed")
    }

    pub async fn stop(mut self) -> anyhow::Result<()> {
        self.stop.store(true, Ordering::Release);
        self.wait().await
    }
}

impl Collector {
    pub fn new(ebpf: &mut Ebpf, directory: &Path) -> anyhow::Result<Self> {
        let (packets, totals) = create_outputs(directory)?;
        Ok(Self {
            ring: RingBuf::try_from(
                ebpf.take_map("PACKET_EVENTS")
                    .context("PACKET_EVENTS missing")?,
            )?,
            stats: PerCpuArray::try_from(
                ebpf.take_map("PACKET_STATS")
                    .context("PACKET_STATS missing")?,
            )?,
            packets,
            totals,
            written: 0,
        })
    }

    pub fn start(self) -> Worker {
        let stop = Arc::new(AtomicBool::new(false));
        let collector_stop = stop.clone();
        let task = tokio::task::spawn_blocking(move || self.run(collector_stop));
        Worker {
            stop,
            task: Some(task),
        }
    }

    pub fn run(mut self, stop: Arc<AtomicBool>) -> anyhow::Result<()> {
        let mut last_flush = Instant::now();
        loop {
            let stopping = stop.load(Ordering::Acquire);
            let consumed = self.consume_batch()?;
            if stopping && consumed < BATCH_SIZE {
                return self.snapshot();
            }
            if last_flush.elapsed() >= FLUSH_INTERVAL {
                self.snapshot()?;
                last_flush = Instant::now();
            }
            if consumed == 0 {
                wait_for_packets(&self.ring)?;
            }
        }
    }

    fn consume_batch(&mut self) -> anyhow::Result<usize> {
        let mut consumed = 0;
        while consumed < BATCH_SIZE {
            let Some(record) = self.ring.next() else {
                break;
            };
            let event = decode_event(&record)?;
            write_event(&mut self.packets, &event)?;
            self.written += 1;
            consumed += 1;
        }
        Ok(consumed)
    }

    fn snapshot(&mut self) -> anyhow::Result<()> {
        self.packets.flush()?;
        let totals = self.read_totals()?;
        self.totals.write_record([
            monotonic_ns()?.to_string(),
            totals.passed.to_string(),
            totals.dropped.to_string(),
            totals.aborted.to_string(),
            totals.lost.to_string(),
            self.written.to_string(),
        ])?;
        self.totals.flush()?;
        Ok(())
    }

    fn read_totals(&self) -> anyhow::Result<PacketStats> {
        let mut totals = PacketStats::default();
        for value in self.stats.get(&0, 0)?.iter() {
            totals.passed += value.passed;
            totals.dropped += value.dropped;
            totals.aborted += value.aborted;
            totals.lost += value.lost;
        }
        Ok(totals)
    }
}

fn create_outputs(directory: &Path) -> anyhow::Result<(Writer<File>, Writer<File>)> {
    std::fs::create_dir_all(directory).context("create packet output directory")?;
    let id = format!(
        "{}-{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        std::process::id()
    );
    let packet_path = directory.join(format!("packets-{id}.csv"));
    let packets = create_csv(&packet_path, PACKET_HEADER, 256 * 1024)?;
    let totals = create_csv(
        &directory.join(format!("stats-{id}.csv")),
        STATS_HEADER,
        8192,
    )?;
    eprintln!("Packet CSV: {}", packet_path.display());
    Ok((packets, totals))
}

fn create_csv(path: &Path, header: &str, capacity: usize) -> anyhow::Result<Writer<File>> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut writer = WriterBuilder::new()
        .buffer_capacity(capacity)
        .from_writer(file);
    writer.write_record(header.split(','))?;
    writer.flush()?;
    Ok(writer)
}

fn decode_event(record: &[u8]) -> anyhow::Result<PacketEvent> {
    if record.len() != std::mem::size_of::<PacketEvent>() {
        bail!("invalid packet event size: {}", record.len());
    }
    // SAFETY: length was checked; PacketEvent contains only integer fields and
    // byte arrays. Ring records are not necessarily aligned for the struct.
    Ok(unsafe { std::ptr::read_unaligned(record.as_ptr().cast::<PacketEvent>()) })
}

fn monotonic_ns() -> std::io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time is a valid writable timespec for the duration of the call.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
}

fn wait_for_packets(ring: &RingBuf<MapData>) -> anyhow::Result<()> {
    let mut fd = libc::pollfd {
        fd: ring.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: fd points to one initialized pollfd and the ring owns its descriptor.
    let result = unsafe { libc::poll(&mut fd, 1, 100) };
    if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
        return Err(std::io::Error::last_os_error().into());
    }
    if fd.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0 {
        bail!("packet ring poll failed");
    }
    Ok(())
}

fn optional_field(valid: bool, value: impl std::fmt::Display) -> String {
    if valid {
        value.to_string()
    } else {
        String::new()
    }
}

fn packet_fields(event: &PacketEvent) -> [String; 12] {
    let valid = |flag| event.valid & flag != 0;
    [
        event.timestamp_monotonic_ns.to_string(),
        event.ifindex.to_string(),
        event.length_bytes.to_string(),
        optional_field(valid(VALID_ETH), event.ethertype),
        optional_field(valid(VALID_IP), Ipv4Addr::from(event.src_ip)),
        optional_field(valid(VALID_IP), Ipv4Addr::from(event.dst_ip)),
        optional_field(valid(VALID_IP), event.ip_protocol),
        optional_field(valid(VALID_PORTS), event.src_port),
        optional_field(valid(VALID_PORTS), event.dst_port),
        optional_field(valid(VALID_TCP), event.tcp_flags),
        mode_name(event.mode).into(),
        action_name(event.action).into(),
    ]
}

fn mode_name(mode: u32) -> &'static str {
    match mode {
        MODE_ALLOW => "allow",
        MODE_BLOCK => "block",
        MODE_FILTER => "filter",
        _ => "unknown",
    }
}

fn action_name(action: u32) -> &'static str {
    match action {
        2 => "PASS",
        1 => "DROP",
        _ => "ABORTED",
    }
}

fn write_event(out: &mut Writer<impl Write>, event: &PacketEvent) -> csv::Result<()> {
    out.write_record(packet_fields(event))
}
