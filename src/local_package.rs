use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use toml::Value;

use crate::config::Config;
use crate::crates::CrateInfo;
use crate::package::PackageExecuteArgs;
use crate::takopack::{self, DebInfo};
use crate::util::write_file_ensuring_dir;

/// Process a local crate directory and generate spec file
pub fn process_local_package(
    path: &Path,
    output_dir: Option<PathBuf>,
    finish_args: PackageExecuteArgs,
) -> Result<()> {
    // Canonicalize the path first to get absolute path
    let path_abs =
        fs::canonicalize(path).with_context(|| format!("Failed to resolve path: {:?}", path))?;

    // Determine the crate directory and Cargo.toml path
    let cargo_toml = if path_abs.is_file() {
        // Path is a .toml file
        if !path_abs.extension().map(|e| e == "toml").unwrap_or(false) {
            anyhow::bail!("File must be a .toml file: {:?}", path_abs);
        }
        path_abs
    } else if path_abs.is_dir() {
        // Path is a directory
        let toml = path_abs.join("Cargo.toml");
        if !toml.exists() {
            anyhow::bail!("Cargo.toml not found in directory: {:?}", path_abs);
        }
        toml
    } else {
        anyhow::bail!(
            "Invalid path: must be a directory or Cargo.toml file: {:?}",
            path_abs
        );
    };

    log::info!("Processing local crate from: {:?}", cargo_toml);

    let temp_crate_dir =
        tempfile::tempdir().context("Failed to create temporary crate directory")?;
    let temp_cargo_toml =
        materialize_manifest_backed_temp_crate(&cargo_toml, temp_crate_dir.path())?;

    log::info!(
        "Temporary crate structure created at: {:?}",
        temp_crate_dir.path()
    );

    // Now process this temporary complete crate with full takopack pipeline
    process_complete_crate(
        temp_crate_dir.path(),
        &temp_cargo_toml,
        output_dir,
        finish_args,
    )
}

fn materialize_manifest_backed_temp_crate(cargo_toml: &Path, temp_dir: &Path) -> Result<PathBuf> {
    let cargo_toml_content = fs::read_to_string(cargo_toml)
        .with_context(|| format!("Failed to read Cargo.toml: {:?}", cargo_toml))?;
    let manifest: Value = toml::from_str(&cargo_toml_content)
        .with_context(|| format!("Failed to parse Cargo.toml: {:?}", cargo_toml))?;

    let temp_cargo_toml = temp_dir.join("Cargo.toml");
    fs::write(&temp_cargo_toml, cargo_toml_content).with_context(|| {
        format!(
            "Failed to write temporary Cargo.toml: {:?}",
            temp_cargo_toml
        )
    })?;

    if let Some(parent) = cargo_toml.parent() {
        let config = parent.join("takopack.toml");
        if config.exists() {
            fs::copy(&config, temp_dir.join("takopack.toml"))
                .with_context(|| format!("Failed to copy takopack.toml from {:?}", config))?;
        }
    }

    materialize_manifest_paths(&manifest, temp_dir)?;
    Ok(temp_cargo_toml)
}

fn materialize_manifest_paths(manifest: &Value, root: &Path) -> Result<()> {
    let mut files = BTreeSet::new();
    let mut explicit_targets = 0usize;

    if let Some(package) = manifest.get("package").and_then(Value::as_table) {
        if let Some(build) = package.get("build") {
            match build {
                Value::Boolean(false) => {}
                Value::String(path) => {
                    files.insert(path.clone());
                }
                _ => {
                    files.insert("build.rs".to_string());
                }
            }
        }

        for key in ["readme", "license-file"] {
            if let Some(path) = package.get(key).and_then(Value::as_str) {
                files.insert(path.to_string());
            }
        }

        if let Some(include) = package.get("include").and_then(Value::as_array) {
            for item in include.iter().filter_map(Value::as_str) {
                if should_materialize_include(item) {
                    files.insert(item.trim_end_matches('/').to_string());
                }
            }
        }
    }

    if let Some(lib) = manifest.get("lib").and_then(Value::as_table) {
        explicit_targets += 1;
        files.insert(
            lib.get("path")
                .and_then(Value::as_str)
                .unwrap_or("src/lib.rs")
                .to_string(),
        );
    }

    for (key, default_dir) in [
        ("bin", "src/bin"),
        ("example", "examples"),
        ("test", "tests"),
        ("bench", "benches"),
    ] {
        if let Some(targets) = manifest.get(key).and_then(Value::as_array) {
            for target in targets.iter().filter_map(Value::as_table) {
                explicit_targets += 1;
                let path = target
                    .get("path")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        target
                            .get("name")
                            .and_then(Value::as_str)
                            .map(|name| format!("{}/{}.rs", default_dir, name))
                    })
                    .unwrap_or_else(|| default_target_path(key).to_string());
                files.insert(path);
            }
        }
    }

    if explicit_targets == 0 {
        files.insert("src/lib.rs".to_string());
    }

    for path in files {
        write_placeholder_file(root, &path)?;
    }

    Ok(())
}

fn default_target_path(kind: &str) -> &'static str {
    match kind {
        "bin" => "src/main.rs",
        "example" => "examples/example.rs",
        "test" => "tests/test.rs",
        "bench" => "benches/bench.rs",
        _ => "src/lib.rs",
    }
}

fn should_materialize_include(path: &str) -> bool {
    !path.starts_with('!')
        && !path.contains('*')
        && !path.contains('?')
        && !path.contains('[')
        && path != "Cargo.toml"
}

fn write_placeholder_file(root: &Path, relative_path: &str) -> Result<()> {
    let relative = safe_manifest_relative_path(relative_path)?;
    let path = root.join(relative);
    if path.exists() {
        return Ok(());
    }

    let content = match path.extension().and_then(|ext| ext.to_str()) {
        Some("rs") => "// Placeholder for takopack localpkg spec generation.\n",
        Some("md") => "# Placeholder\n",
        _ => "Placeholder for takopack localpkg spec generation.\n",
    };
    write_file_ensuring_dir(&path, content)
}

fn safe_manifest_relative_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    if path.is_absolute() {
        anyhow::bail!("Cargo.toml path must be relative for localpkg: {:?}", path);
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        anyhow::bail!("Cargo.toml path escapes the temporary crate: {:?}", path);
    }
    Ok(path.to_path_buf())
}

/// Process a complete crate directory (with src/) using full takopack pipeline
fn process_complete_crate(
    temp_crate_dir: &Path,
    cargo_toml: &Path,
    output_dir: Option<PathBuf>,
    finish_args: PackageExecuteArgs,
) -> Result<()> {
    // Load config if available
    let config_path = temp_crate_dir.join("takopack.toml");
    let (config_path, config) = if config_path.exists() {
        let config = Config::parse(&config_path).context("failed to parse takopack.toml")?;
        (Some(config_path), config)
    } else {
        (None, Config::default())
    };

    // Create CrateInfo from local crate (now it has src/ so Cargo APIs will work)
    let mut crate_info = CrateInfo::new_with_local_crate_from_path(cargo_toml)
        .with_context(|| format!("Failed to load crate from: {:?}", cargo_toml))?;

    let crate_name = crate_info.crate_name();
    // It's a full version,like "0.9.11+spec-1.1.0"
    let version = crate_info.version();

    log::info!("Crate: {} {}", crate_name, version);

    // Create DebInfo
    let deb_info = DebInfo::new(&crate_info, env!("CARGO_PKG_VERSION"), config.semver_suffix);

    let output_names = crate::util::rust_crate_output_names(crate_name, version);

    // Determine output directory
    let output_base = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let final_output = output_base.join(&output_names.directory);

    fs::create_dir_all(&final_output)
        .with_context(|| format!("Failed to create output directory: {:?}", final_output))?;

    // Create a temporary directory for takopack processing
    let tempdir =
        tempfile::tempdir_in(temp_crate_dir).context("Failed to create temporary directory")?;

    log::info!("Tempdir created at: {:?}", tempdir.path());
    log::info!("Preparing takopack folder");

    // Apply overrides and generate spec file
    let prepare_result = takopack::prepare_takopack_folder(
        &mut crate_info,
        &deb_info,
        config_path.as_deref(),
        &config,
        temp_crate_dir,
        &tempdir,
        finish_args.changelog_ready,
        finish_args.copyright_guess_harder,
        !finish_args.no_overlay_write_back,
        None, // TODO: sha256: local packages don't have downloaded crate files, maybe consider record the sha256 when use pkg.
        finish_args.lockfile_deps, // Pass lockfile dependencies if available
    );

    if let Err(e) = &prepare_result {
        log::error!("prepare_takopack_folder failed: {:?}", e);
    }
    prepare_result?;

    // Note: prepare_takopack_folder renames tempdir to output_dir/takopack
    let takopack_dir = temp_crate_dir.join("takopack");
    log::info!("Takopack folder should be at: {:?}", takopack_dir);
    log::info!("Takopack dir exists: {}", takopack_dir.exists());

    // Copy spec file to output directory
    let source_spec = takopack_dir.join(&output_names.spec_file);
    let final_spec = final_output.join(&output_names.spec_file);

    // List files in takopack dir for debugging
    log::debug!("Listing files in takopack dir: {:?}", takopack_dir);
    match fs::read_dir(&takopack_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                log::debug!("  - {:?}", entry.file_name());
            }
        }
        Err(e) => {
            log::error!("Failed to read takopack dir: {:?}", e);
        }
    }

    if source_spec.exists() {
        fs::copy(&source_spec, &final_spec)
            .with_context(|| format!("Failed to copy spec file to: {:?}", final_spec))?;
        crate::util::copy_original_cargo_toml_to_dir(temp_crate_dir, &final_output)?;

        log::info!("Spec file saved to: {}", final_spec.display());
        println!("Spec file: {}", final_spec.display());
    } else {
        anyhow::bail!("Spec file not found at: {:?}", source_spec);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::materialize_manifest_backed_temp_crate;
    use std::fs;

    #[test]
    fn localpkg_materializes_declared_manifest_paths() {
        let source = tempfile::tempdir().unwrap();
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            source.path().join("Cargo.toml"),
            r#"
[package]
name = "shape"
version = "1.2.3"
edition = "2021"
build = "build/main.rs"
readme = "docs/README.md"
license-file = "licenses/LICENSE.txt"
include = ["NOTICE"]

[lib]
path = "src/shape/lib.rs"

[[bin]]
name = "shape-cli"
path = "cli/main.rs"

[[example]]
name = "demo"
"#,
        )
        .unwrap();
        fs::write(source.path().join("takopack.toml"), "[source]\n").unwrap();

        materialize_manifest_backed_temp_crate(&source.path().join("Cargo.toml"), temp.path())
            .unwrap();

        for path in [
            "Cargo.toml",
            "takopack.toml",
            "build/main.rs",
            "docs/README.md",
            "licenses/LICENSE.txt",
            "NOTICE",
            "src/shape/lib.rs",
            "cli/main.rs",
            "examples/demo.rs",
        ] {
            assert!(temp.path().join(path).exists(), "missing {path}");
        }
    }

    #[test]
    fn localpkg_adds_default_lib_for_manifest_without_targets() {
        let source = tempfile::tempdir().unwrap();
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            source.path().join("Cargo.toml"),
            r#"
[package]
name = "minimal"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();

        materialize_manifest_backed_temp_crate(&source.path().join("Cargo.toml"), temp.path())
            .unwrap();

        assert!(temp.path().join("src/lib.rs").exists());
    }
}
