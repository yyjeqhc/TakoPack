//! Resolve-check subcommand.
//!
//! Given a directory or `Cargo.toml` file, verify that Cargo can
//! successfully resolve (generate a lockfile) using only the TakoPack
//! local directory registry in offline mode.
//!
//! ## Current limitations (MVP)
//!
//! * The check always copies only `Cargo.toml` into a temporary directory
//!   rather than cloning the entire project tree.  This means workspace
//!   manifests, path dependencies, and build scripts that reference local
//!   files will not work until a future version adds full-tree copy.
//! * No structured error analysis (need_add / need_update) is performed;
//!   the raw Cargo stderr is forwarded on failure.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;

use crate::config::load_takopack_toml;
use crate::errors::Result;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the `resolve-check` subcommand.
///
/// Returns an exit code: 0 = resolve succeeded, 1 = failed or error.
pub fn run_resolve_check(path: &Path) -> Result<i32> {
    // 1. Determine manifest path and working directory.
    let (manifest, _workdir) = resolve_manifest(path)?;

    // 2. Determine registry directory.
    let registry_dir = resolve_registry_dir()?;
    if !registry_dir.is_dir() {
        takopack_bail!(
            "local registry directory does not exist: {}\n\
             Run `takopack cargo registry-sync` first.",
            registry_dir.display()
        );
    }

    println!("Resolve check");
    println!("  manifest: {}", manifest.display());
    println!("  registry: {}", registry_dir.display());

    // 3. Try real mode first.
    let (real_ok, real_stderr) = try_resolve(&manifest, &registry_dir, "real")?;

    if real_ok {
        println!("  mode: real");
        println!();
        println!("Result: ok");
        return Ok(0);
    }

    // 4. Check if real mode failed due to "no targets" – if so, retry with
    //    virtual mode.
    if is_no_targets_error(&real_stderr) {
        eprintln!();
        eprintln!("real mode failed with no targets; retrying in virtual mode");

        let (virtual_ok, virtual_stderr) = try_resolve_virtual(&manifest, &registry_dir)?;

        println!("  mode: virtual (fallback)");
        println!();

        if virtual_ok {
            println!("Result: ok");
            return Ok(0);
        }

        println!("Result: failed");
        if !virtual_stderr.is_empty() {
            eprintln!("{}", virtual_stderr);
        }
        return Ok(1);
    }

    // 5. Real mode failed for a resolve / dependency reason – report as-is.
    println!("  mode: real");
    println!();
    println!("Result: failed");
    if !real_stderr.is_empty() {
        eprintln!("{}", real_stderr);
    }
    Ok(1)
}

// ---------------------------------------------------------------------------
// Manifest / path resolution
// ---------------------------------------------------------------------------

fn resolve_manifest(path: &Path) -> Result<(PathBuf, PathBuf)> {
    if path.is_dir() {
        let manifest = path.join("Cargo.toml");
        if !manifest.is_file() {
            takopack_bail!("no Cargo.toml found in directory: {}", path.display());
        }
        Ok((manifest, path.to_path_buf()))
    } else if path.is_file() {
        let workdir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Ok((path.to_path_buf(), workdir))
    } else {
        takopack_bail!("path does not exist: {}", path.display());
    }
}

// ---------------------------------------------------------------------------
// Registry directory resolution
// ---------------------------------------------------------------------------

fn resolve_registry_dir() -> Result<PathBuf> {
    // Try takopack.toml first.
    if let Some((_config_path, config)) = load_takopack_toml()? {
        if let Some(registry) = config.registry {
            if let Some(local_path) = registry.local_path {
                let path = if local_path.is_absolute() {
                    local_path
                } else {
                    _config_path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(local_path)
                };
                return Ok(path);
            }
        }
    }

    // Fall back to the same default as registry-sync.
    default_registry_dir()
}

/// `$XDG_DATA_HOME/takopack/cargo-registry` or
/// `~/.local/share/takopack/cargo-registry`.
fn default_registry_dir() -> Result<PathBuf> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        anyhow::anyhow!("cannot determine XDG_DATA_HOME / home directory for default registry path")
    })?;
    Ok(data_dir.join("takopack").join("cargo-registry"))
}

// ---------------------------------------------------------------------------
// Resolve execution helpers
// ---------------------------------------------------------------------------

/// Run `cargo generate-lockfile` in a temporary copy of the manifest, using
/// the local registry as a crates-io replacement in offline mode.
///
/// Returns `(success, stderr_text)`.
fn try_resolve(manifest: &Path, registry_dir: &Path, label: &str) -> Result<(bool, String)> {
    let tmp =
        tempfile::tempdir().context("failed to create temporary directory for resolve check")?;
    let tmp_path = tmp.path();

    // Copy Cargo.toml into the temp dir.
    fs::copy(manifest, tmp_path.join("Cargo.toml"))
        .with_context(|| format!("failed to copy {} to tempdir", manifest.display()))?;

    // If the manifest lives alongside a src/ directory, copy it so that
    // Cargo can find at least one target.
    let parent = manifest.parent().unwrap_or_else(|| Path::new("."));
    let src_dir = parent.join("src");
    if src_dir.is_dir() {
        copy_dir_simple(&src_dir, &tmp_path.join("src"))?;
    }

    // Write .cargo/config.toml to replace crates-io with local registry.
    write_cargo_config(tmp_path, registry_dir)?;

    log::debug!(
        "resolve-check [{}]: running cargo generate-lockfile in {}",
        label,
        tmp_path.display()
    );

    run_cargo_generate_lockfile(tmp_path)
}

/// Virtual mode: copy Cargo.toml and create a stub `src/lib.rs`.
fn try_resolve_virtual(manifest: &Path, registry_dir: &Path) -> Result<(bool, String)> {
    let tmp = tempfile::tempdir()
        .context("failed to create temporary directory for virtual resolve check")?;
    let tmp_path = tmp.path();

    fs::copy(manifest, tmp_path.join("Cargo.toml"))
        .with_context(|| format!("failed to copy {} to tempdir", manifest.display()))?;

    // Create stub source so Cargo has a target.
    let src = tmp_path.join("src");
    fs::create_dir_all(&src)?;
    fs::write(src.join("lib.rs"), "")?;

    write_cargo_config(tmp_path, registry_dir)?;

    log::debug!(
        "resolve-check [virtual]: running cargo generate-lockfile in {}",
        tmp_path.display()
    );

    run_cargo_generate_lockfile(tmp_path)
}

/// Write `.cargo/config.toml` that replaces `crates-io` with the local
/// directory registry and enables offline mode.
fn write_cargo_config(project_dir: &Path, registry_dir: &Path) -> Result<()> {
    let cargo_dir = project_dir.join(".cargo");
    fs::create_dir_all(&cargo_dir)?;

    let config_content = format!(
        r#"[source.crates-io]
replace-with = "takopack-local"

[source.takopack-local]
directory = "{}"

[net]
offline = true
"#,
        registry_dir.display()
    );

    fs::write(cargo_dir.join("config.toml"), config_content)?;
    Ok(())
}

/// Invoke `cargo generate-lockfile` in the given directory and capture output.
fn run_cargo_generate_lockfile(project_dir: &Path) -> Result<(bool, String)> {
    let output = Command::new("cargo")
        .arg("generate-lockfile")
        .current_dir(project_dir)
        .env("CARGO_HOME", project_dir.join(".cargo-home"))
        .output()
        .context("failed to execute `cargo generate-lockfile`")?;

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    if !stdout.is_empty() {
        log::debug!("cargo stdout:\n{}", stdout);
    }
    if !stderr.is_empty() {
        log::debug!("cargo stderr:\n{}", stderr);
    }

    Ok((output.status.success(), stderr))
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

/// Return `true` if the Cargo error indicates a bare manifest with no
/// targets (missing src/lib.rs, src/main.rs, etc.).
fn is_no_targets_error(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("no targets specified in the manifest")
        || lower.contains("can't find")
            && (lower.contains("src/lib.rs") || lower.contains("src/main.rs"))
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

/// Recursively copy a directory tree.  Not performance-critical for MVP.
fn copy_dir_simple(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_simple(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_no_targets_error_positive() {
        assert!(is_no_targets_error(
            "error: failed to parse manifest\n\
             Caused by:\n  no targets specified in the manifest\n"
        ));
    }

    #[test]
    fn test_is_no_targets_error_src_lib() {
        assert!(is_no_targets_error(
            "error: can't find `src/lib.rs` or `src/main.rs`"
        ));
    }

    #[test]
    fn test_is_no_targets_error_negative() {
        assert!(!is_no_targets_error(
            "error: failed to select a version for `serde`"
        ));
    }

    #[test]
    fn test_resolve_manifest_dir() {
        // Create a temp directory with a Cargo.toml
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();

        let (m, w) = resolve_manifest(tmp.path()).unwrap();
        assert_eq!(m, manifest);
        assert_eq!(w, tmp.path());
    }

    #[test]
    fn test_resolve_manifest_file() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();

        let (m, w) = resolve_manifest(&manifest).unwrap();
        assert_eq!(m, manifest);
        assert_eq!(w, tmp.path());
    }

    #[test]
    fn test_resolve_manifest_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let result = resolve_manifest(tmp.path());
        assert!(result.is_err());
    }
}
