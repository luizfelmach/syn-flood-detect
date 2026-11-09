use std::{
    num::{NonZeroU32, NonZeroU64},
    path::PathBuf,
};

use clap::{Args, Parser, Subcommand};
use syn_flood_detect_common::{FirewallConfig, UBF_ENTRIES};

use crate::control::{ConfigUpdate, HashAlgorithm, Mode};

#[derive(Debug, Parser)]
#[command(about = "Configure an XDP SYN flood detector and record packet decisions")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Load and attach the firewall, then collect packet decisions until stopped.
    Run(RunOptions),
    /// Change how the running firewall handles packets.
    Mode {
        #[arg(value_name = "MODE")]
        packet_handling_mode: Mode,
    },
    /// Update detector parameters without restarting. Changing UBF size or hash clears history; pause traffic for a consistent transition.
    Config(ConfigOptions),
    /// Show the running mode and detector parameters.
    Show,
    /// Clear detector history while leaving traffic processing and statistics unchanged.
    Reset,
}

#[derive(Debug, Args)]
pub struct RunOptions {
    #[arg(short, long, default_value = "eth0")]
    pub iface: String,
    #[arg(long, default_value = "results/packets")]
    pub packet_dir: PathBuf,
    #[arg(
        long = "mode",
        value_name = "MODE",
        value_enum,
        default_value = "filter"
    )]
    packet_handling_mode: Mode,
    #[arg(long)]
    epoch_time_ms: Option<NonZeroU64>,
    #[arg(long)]
    syn_count_block_threshold: Option<NonZeroU32>,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=i64::from(UBF_ENTRIES)))]
    ubf_size: Option<u32>,
    #[arg(long, value_enum, help = "Hash algorithm (default: halfsiphash)")]
    hash_algorithm: Option<HashAlgorithm>,
}

impl RunOptions {
    pub fn config(&self) -> FirewallConfig {
        let defaults = FirewallConfig::default();
        FirewallConfig {
            packet_handling_mode: self.packet_handling_mode.value(),
            ubf_size: self.ubf_size.unwrap_or(defaults.ubf_size),
            hash_algorithm: self.hash_algorithm.unwrap_or_default().value(),
            epoch_time_ms: self
                .epoch_time_ms
                .map(NonZeroU64::get)
                .unwrap_or(defaults.epoch_time_ms),
            syn_count_block_threshold: self
                .syn_count_block_threshold
                .map(NonZeroU32::get)
                .unwrap_or(defaults.syn_count_block_threshold),
        }
    }
}

#[derive(Debug, Args)]
#[group(required = true, multiple = true)]
pub struct ConfigOptions {
    #[arg(long)]
    epoch_time_ms: Option<NonZeroU64>,
    #[arg(long)]
    syn_count_block_threshold: Option<NonZeroU32>,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=i64::from(UBF_ENTRIES)))]
    ubf_size: Option<u32>,
    #[arg(long, value_enum)]
    hash_algorithm: Option<HashAlgorithm>,
}

impl From<ConfigOptions> for ConfigUpdate {
    fn from(options: ConfigOptions) -> Self {
        Self {
            epoch_time_ms: options.epoch_time_ms,
            ubf_size: options.ubf_size,
            hash_algorithm: options.hash_algorithm,
            syn_count_block_threshold: options.syn_count_block_threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn_flood_detect_common::hashing::*;

    #[test]
    fn defaults_and_explicit_selection() {
        let Command::Run(run) = Cli::try_parse_from(["detector", "run"]).unwrap().command else {
            panic!()
        };
        assert_eq!(run.config().hash_algorithm, HASH_HALFSIPHASH);
        for (name, id) in [
            ("fnv1a", HASH_FNV1A),
            ("murmur3", HASH_MURMUR3),
            ("halfsiphash", HASH_HALFSIPHASH),
        ] {
            let Command::Run(run) =
                Cli::try_parse_from(["detector", "run", "--hash-algorithm", name])
                    .unwrap()
                    .command
            else {
                panic!()
            };
            assert_eq!(run.config().hash_algorithm, id);
            let Command::Config(config) =
                Cli::try_parse_from(["detector", "config", "--hash-algorithm", name])
                    .unwrap()
                    .command
            else {
                panic!()
            };
            assert_eq!(
                ConfigUpdate::from(config).hash_algorithm.unwrap().value(),
                id
            );
        }
        assert!(
            Cli::try_parse_from(["detector", "config", "--hash-algorithm", "invalid"]).is_err()
        );
        assert!(Cli::try_parse_from(["detector", "config"]).is_err());
    }
}
