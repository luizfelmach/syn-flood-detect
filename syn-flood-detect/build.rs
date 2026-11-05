use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed=EBPF_TOOLCHAIN");
    println!("cargo:rerun-if-changed=../syn-flood-detect-common/src");
    let package = find_ebpf_package()?;
    let toolchain = std::env::var("EBPF_TOOLCHAIN").unwrap_or_else(|_| "nightly".into());
    build_ebpf(&package, &toolchain)
}

fn find_ebpf_package() -> anyhow::Result<cargo_metadata::Package> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    metadata
        .packages
        .into_iter()
        .find(|package| package.name.as_str() == "syn-flood-detect-ebpf")
        .ok_or_else(|| anyhow!("syn-flood-detect-ebpf package not found"))
}

fn build_ebpf(package: &cargo_metadata::Package, toolchain: &str) -> anyhow::Result<()> {
    let package = aya_build::Package {
        name: package.name.as_str(),
        root_dir: package
            .manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {}", package.manifest_path))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([package], Toolchain::Custom(toolchain))
}
