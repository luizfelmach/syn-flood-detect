use anyhow::Context;
use aya::programs::{Xdp, XdpMode};
use clap::Parser;
use tokio::signal;

mod cli;
mod control;
mod telemetry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = match cli::Cli::parse().command {
        cli::Command::Run(options) => options,
        cli::Command::Mode {
            packet_handling_mode,
        } => {
            return control::send(control::Request::Mode {
                packet_handling_mode,
            })
            .await;
        }
        cli::Command::Config(options) => {
            return control::send(control::Request::Config(options.into())).await;
        }
        cli::Command::Show => return control::send(control::Request::Show {}).await,
        cli::Command::Reset => return control::send(control::Request::Reset {}).await,
    };

    env_logger::init();
    remove_memlock_limit();
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/syn-flood-detect"
    )))?;
    let socket = control::ControlSocket::bind()?;
    let mut controller = control::Controller::new(&mut ebpf, options.config())?;
    let collector = telemetry::Collector::new(&mut ebpf, &options.packet_dir)?;

    let program: &mut Xdp = ebpf
        .program_mut("syn_flood_detect")
        .context("missing syn_flood_detect program")?
        .try_into()?;
    program.load()?;
    let link = program.attach(&options.iface, XdpMode::default()).context(
        "failed to attach XDP with default mode; the interface may require XdpMode::Skb",
    )?;
    let mut worker = collector.start();
    println!("Firewall: {}", controller.snapshot());

    let outcome = wait_for_exit(&mut controller, &socket, &mut worker).await;
    let detached = program
        .detach(link)
        .context("detach XDP before draining packets");
    drop(ebpf);
    let drained = worker.stop().await;
    detached?;
    drained?;
    outcome?;
    println!("Exiting...");
    Ok(())
}

fn remove_memlock_limit() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: limit is an initialized rlimit valid for the duration of the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } != 0 {
        log::debug!(
            "remove limit on locked memory failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

async fn wait_for_exit(
    controller: &mut control::Controller,
    socket: &control::ControlSocket,
    worker: &mut telemetry::Worker,
) -> anyhow::Result<()> {
    tokio::select! {
        result = controller.serve(socket) => result,
        result = shutdown_signal() => result,
        result = worker.wait() => result.and_then(|()| {
            anyhow::bail!("packet collector stopped unexpectedly")
        }),
    }
}

async fn shutdown_signal() -> anyhow::Result<()> {
    let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = signal::ctrl_c() => result.map_err(Into::into),
        _ = terminate.recv() => Ok(()),
    }
}
