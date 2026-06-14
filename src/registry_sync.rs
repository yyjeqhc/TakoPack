//! Registry-sync subcommand.
//!
//! Synchronises a local Cargo registry directory from the set of Rust crate
//! providers declared in a ruyispec repository.  The resulting directory
//! layout mirrors what Cargo expects under `$CARGO_HOME/registry/src/` so
//! that it can be used as a path-based registry source.
//!
//! High-level flow:
//! 1. Scan `SPECS/rust-*/*.spec` for `%global crate_name` / `%global full_version`.
//! 2. Compare the scan against a persisted index (`.takopack/index.json`).
//! 3. Download, extract, and patch changed / new crates.
//! 4. Remove stale entries and orphan directories.
//! 5. Write the updated index atomically.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::Context;
use flate2::read::GzDecoder;
use glob::glob;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::config::load_takopack_toml;
use crate::errors::Result;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the `registry-sync` subcommand.
///
/// Returns an exit code (0 = success, 1 = warnings present).
pub fn run_registry_sync(dry_run: bool) -> Result<i32> {
    let (ruyispec_dir, registry_dir) = resolve_paths()?;

    println!("Registry sync");
    println!("  ruyispec: {}", ruyispec_dir.display());
    println!("  registry: {}", registry_dir.display());
    if dry_run {
        println!("  (dry-run mode — no files will be modified)");
    }
    println!();

    // 1. Scan providers
    let current = scan_providers(&ruyispec_dir)?;
    log::info!("scanned {} provider(s)", current.len());

    // 2. Load existing index
    let old_index = load_index(&registry_dir)?;

    // 3. Reconcile
    let plan = reconcile(&current, &old_index, &registry_dir);
    log::debug!("plan: {:?}", plan.summary());

    // 4. Execute (or just report in dry-run mode)
    let mut warnings: usize = 0;

    // --- adds ---
    for spec_key in &plan.add {
        let entry = &current[spec_key];
        if dry_run {
            println!("  [add] {} → {}", spec_key, entry.registry_path);
        } else {
            log::info!("adding {}", entry.registry_path);
            if let Err(e) = sync_crate(entry, &ruyispec_dir, &registry_dir) {
                takopack_warn!("failed to add {}: {:#}", entry.registry_path, e);
                warnings += 1;
            }
        }
    }

    // --- updates ---
    for spec_key in &plan.update {
        let entry = &current[spec_key];
        if dry_run {
            println!("  [update] {} → {}", spec_key, entry.registry_path);
        } else {
            log::info!("updating {}", entry.registry_path);
            if let Err(e) = sync_crate(entry, &ruyispec_dir, &registry_dir) {
                takopack_warn!("failed to update {}: {:#}", entry.registry_path, e);
                warnings += 1;
            }
        }
    }

    // --- removes ---
    for spec_key in &plan.remove {
        let entry = &old_index.entries[spec_key];
        let dir = registry_dir.join(&entry.registry_path);
        if dry_run {
            println!("  [remove] {} ({})", spec_key, entry.registry_path);
        } else {
            log::info!("removing {}", entry.registry_path);
            if dir.is_dir() {
                if let Err(e) = fs::remove_dir_all(&dir) {
                    takopack_warn!("failed to remove {}: {}", dir.display(), e);
                    warnings += 1;
                }
            }
        }
    }

    // --- skips ---
    for spec_key in &plan.skip {
        log::debug!("unchanged: {}", spec_key);
    }

    // 5. Clean orphan directories
    if !dry_run {
        warnings += clean_orphans(&registry_dir, &current);
    }

    // 6. Write new index
    if !dry_run {
        let new_index = build_index(&current);
        write_index(&registry_dir, &new_index)?;
    }

    // 7. Summary
    println!();
    println!("Summary:");
    println!("  add={}", plan.add.len());
    println!("  update={}", plan.update.len());
    println!("  remove={}", plan.remove.len());
    println!("  skip={}", plan.skip.len());
    println!("  warnings={}", warnings);

    if warnings > 0 {
        Ok(1)
    } else {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

/// Resolve the ruyispec directory and registry directory from `takopack.toml`.
fn resolve_paths() -> Result<(PathBuf, PathBuf)> {
    let (config_path, config) = load_takopack_toml()?.ok_or_else(|| {
        anyhow::anyhow!(
            "missing takopack.toml; create one with [ruyispec].local_path and optionally [registry].local_path"
        )
    })?;

    // Ruyispec
    let ruyispec_local = config
        .ruyispec
        .and_then(|r| r.local_path)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} does not define [ruyispec].local_path",
                config_path.display()
            )
        })?;
    let ruyispec_dir = if ruyispec_local.is_absolute() {
        ruyispec_local
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(ruyispec_local)
    };
    if !ruyispec_dir.is_dir() {
        takopack_bail!(
            "ruyispec directory does not exist: {}",
            ruyispec_dir.display()
        );
    }

    // Registry
    let registry_dir = if let Some(registry_local) = config.registry.and_then(|r| r.local_path) {
        if registry_local.is_absolute() {
            registry_local
        } else {
            config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(registry_local)
        }
    } else {
        default_registry_dir()?
    };

    Ok((ruyispec_dir, registry_dir))
}

/// `$XDG_DATA_HOME/takopack/cargo-registry` or `~/.local/share/takopack/cargo-registry`.
fn default_registry_dir() -> Result<PathBuf> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        anyhow::anyhow!("cannot determine XDG_DATA_HOME / home directory for default registry path")
    })?;
    Ok(data_dir.join("takopack").join("cargo-registry"))
}

// ---------------------------------------------------------------------------
// Provider scanning
// ---------------------------------------------------------------------------

/// Information extracted from a single `.spec` file.
#[derive(Debug, Clone)]
struct ProviderEntry {
    /// Relative path to the spec file from the ruyispec root, e.g.
    /// `SPECS/rust-tokio-1/rust-tokio-1.spec`.
    spec_key: String,
    /// Crate name as declared via `%global crate_name`.
    crate_name: String,
    /// Crate version as declared via `%global full_version`.
    version: String,
    /// RPM name derived from the directory name (e.g. `rust-tokio-1`).
    rpm_name: String,
    /// Registry sub-directory, `{crate_name}-{version}`.
    registry_path: String,
    /// SHA-256 hex digest of the spec file contents.
    spec_hash: String,
    /// SHA-256 hex digest of the provider `Cargo.toml`, if present.
    cargo_toml_hash: Option<String>,
}

/// Scan `{ruyispec}/SPECS/rust-*/*.spec` and return a map keyed by `spec_key`.
fn scan_providers(ruyispec_dir: &Path) -> Result<BTreeMap<String, ProviderEntry>> {
    let pattern = format!("{}/SPECS/rust-*/*.spec", ruyispec_dir.display());
    let re_crate = Regex::new(r"^%global\s+crate_name\s+(\S+)")
        .expect("regex");
    let re_version = Regex::new(r"^%global\s+full_version\s+(\S+)")
        .expect("regex");

    let mut providers = BTreeMap::new();

    for entry in glob(&pattern).context("invalid glob pattern")? {
        let spec_path = entry.context("glob error")?;
        let content = fs::read_to_string(&spec_path)
            .with_context(|| format!("failed to read {}", spec_path.display()))?;

        // Parse %global macros
        let mut crate_name: Option<String> = None;
        let mut version: Option<String> = None;
        for line in content.lines() {
            if let Some(caps) = re_crate.captures(line) {
                crate_name = Some(caps[1].to_string());
            }
            if let Some(caps) = re_version.captures(line) {
                version = Some(caps[1].to_string());
            }
            if crate_name.is_some() && version.is_some() {
                break;
            }
        }

        let crate_name = match crate_name {
            Some(n) => n,
            None => {
                log::warn!(
                    "skipping {} (no %global crate_name found)",
                    spec_path.display()
                );
                continue;
            }
        };
        let version = match version {
            Some(v) => v,
            None => {
                log::warn!(
                    "skipping {} (no %global full_version found)",
                    spec_path.display()
                );
                continue;
            }
        };

        // Directory-based RPM name
        let spec_dir = spec_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("spec file has no parent dir"))?;
        let rpm_name = spec_dir
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("cannot extract dir name for {}", spec_path.display()))?
            .to_string_lossy()
            .to_string();

        // Relative spec_key
        let spec_key = spec_path
            .strip_prefix(ruyispec_dir)
            .with_context(|| {
                format!(
                    "{} is not under {}",
                    spec_path.display(),
                    ruyispec_dir.display()
                )
            })?
            .to_string_lossy()
            .replace('\\', "/");

        let spec_hash = sha256_hex(content.as_bytes());

        // Optional provider Cargo.toml
        let cargo_toml_path = spec_dir.join("Cargo.toml");
        let cargo_toml_hash = if cargo_toml_path.is_file() {
            let cargo_bytes = fs::read(&cargo_toml_path)
                .with_context(|| format!("failed to read {}", cargo_toml_path.display()))?;
            Some(sha256_hex(&cargo_bytes))
        } else {
            None
        };

        let registry_path = format!("{}-{}", crate_name, version);

        providers.insert(
            spec_key.clone(),
            ProviderEntry {
                spec_key,
                crate_name,
                version,
                rpm_name,
                registry_path,
                spec_hash,
                cargo_toml_hash,
            },
        );
    }

    Ok(providers)
}

// ---------------------------------------------------------------------------
// Persistent index
// ---------------------------------------------------------------------------

/// On-disk index stored at `{registry}/.takopack/index.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryIndex {
    schema_version: u32,
    entries: BTreeMap<String, IndexEntry>,
}

/// One entry in the persisted index.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexEntry {
    crate_name: String,
    version: String,
    rpm_name: String,
    registry_path: String,
    spec_hash: String,
    cargo_toml_hash: Option<String>,
}

impl RegistryIndex {
    fn empty() -> Self {
        Self {
            schema_version: 1,
            entries: BTreeMap::new(),
        }
    }
}

fn load_index(registry_dir: &Path) -> Result<RegistryIndex> {
    let path = registry_dir.join(".takopack").join("index.json");
    if !path.is_file() {
        return Ok(RegistryIndex::empty());
    }
    let data = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let index: RegistryIndex = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(index)
}

fn build_index(providers: &BTreeMap<String, ProviderEntry>) -> RegistryIndex {
    let entries = providers
        .iter()
        .map(|(key, p)| {
            (
                key.clone(),
                IndexEntry {
                    crate_name: p.crate_name.clone(),
                    version: p.version.clone(),
                    rpm_name: p.rpm_name.clone(),
                    registry_path: p.registry_path.clone(),
                    spec_hash: p.spec_hash.clone(),
                    cargo_toml_hash: p.cargo_toml_hash.clone(),
                },
            )
        })
        .collect();

    RegistryIndex {
        schema_version: 1,
        entries,
    }
}

/// Atomically write the index: write to a temporary file then rename.
fn write_index(registry_dir: &Path, index: &RegistryIndex) -> Result<()> {
    let dir = registry_dir.join(".takopack");
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;

    let final_path = dir.join("index.json");
    let tmp_path = dir.join("index.json.tmp");

    let json = serde_json::to_string_pretty(index)?;
    fs::write(&tmp_path, json.as_bytes())
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, &final_path)
        .with_context(|| format!("failed to rename {} → {}", tmp_path.display(), final_path.display()))?;

    log::info!("wrote {}", final_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

/// Actions determined by comparing the current scan against the persisted index.
#[derive(Debug)]
struct SyncPlan {
    add: Vec<String>,
    update: Vec<String>,
    remove: Vec<String>,
    skip: Vec<String>,
}

impl SyncPlan {
    fn summary(&self) -> String {
        format!(
            "add={} update={} remove={} skip={}",
            self.add.len(),
            self.update.len(),
            self.remove.len(),
            self.skip.len(),
        )
    }
}

fn reconcile(
    current: &BTreeMap<String, ProviderEntry>,
    old_index: &RegistryIndex,
    registry_dir: &Path,
) -> SyncPlan {
    let mut add = Vec::new();
    let mut update = Vec::new();
    let mut skip = Vec::new();
    let mut remove = Vec::new();

    for (key, entry) in current {
        match old_index.entries.get(key) {
            None => add.push(key.clone()),
            Some(old) => {
                let hashes_match =
                    old.spec_hash == entry.spec_hash && old.cargo_toml_hash == entry.cargo_toml_hash;
                let dir_exists = registry_dir.join(&entry.registry_path).is_dir();

                if hashes_match && dir_exists {
                    skip.push(key.clone());
                } else {
                    update.push(key.clone());
                }
            }
        }
    }

    for key in old_index.entries.keys() {
        if !current.contains_key(key) {
            remove.push(key.clone());
        }
    }

    SyncPlan {
        add,
        update,
        remove,
        skip,
    }
}

// ---------------------------------------------------------------------------
// Crate download / extract / patch
// ---------------------------------------------------------------------------

/// Download a crate tarball from crates.io, extract it, optionally overlay
/// the provider `Cargo.toml`, and regenerate `.cargo-checksum.json`.
fn sync_crate(
    entry: &ProviderEntry,
    ruyispec_dir: &Path,
    registry_dir: &Path,
) -> Result<()> {
    let dest = registry_dir.join(&entry.registry_path);

    // Remove any previous directory so we start clean.
    if dest.exists() {
        fs::remove_dir_all(&dest)
            .with_context(|| format!("failed to remove old {}", dest.display()))?;
    }
    fs::create_dir_all(&dest)
        .with_context(|| format!("failed to create {}", dest.display()))?;

    // Download
    let url = format!(
        "https://static.crates.io/crates/{}/{}/download",
        entry.crate_name, entry.version
    );
    log::info!("downloading {}", url);
    let resp = ureq::get(&url)
        .call()
        .with_context(|| format!("HTTP request failed for {}", url))?;

    let mut body = Vec::new();
    resp.into_reader()
        .read_to_end(&mut body)
        .with_context(|| format!("failed to read response body from {}", url))?;

    // Extract (gzipped tar)
    extract_tarball(&body, &dest, &entry.registry_path)?;

    // Overlay provider Cargo.toml if present
    let spec_dir = ruyispec_dir.join(
        Path::new(&entry.spec_key)
            .parent()
            .unwrap_or_else(|| Path::new("")),
    );
    let provider_cargo = spec_dir.join("Cargo.toml");
    if provider_cargo.is_file() {
        let dest_cargo = dest.join("Cargo.toml");
        fs::copy(&provider_cargo, &dest_cargo).with_context(|| {
            format!(
                "failed to copy {} → {}",
                provider_cargo.display(),
                dest_cargo.display()
            )
        })?;
        log::debug!(
            "overlaid provider Cargo.toml for {}",
            entry.registry_path
        );
    } else {
        log::warn!(
            "{}: no provider Cargo.toml, keeping crates.io original",
            entry.spec_key
        );
    }

    // Regenerate .cargo-checksum.json
    write_cargo_checksum(&dest)?;

    Ok(())
}

/// Extract a gzipped tarball into `dest`, stripping the common top-level
/// directory prefix (which is typically `{crate_name}-{version}/`).
fn extract_tarball(tarball: &[u8], dest: &Path, _expected_prefix: &str) -> Result<()> {
    let gz = GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(gz);

    for file in archive.entries().context("failed to read tar entries")? {
        let mut file = file.context("corrupt tar entry")?;
        let raw_path = file.path().context("bad tar entry path")?.into_owned();

        // Strip the top-level directory.  Most crates.io tarballs contain
        // `{name}-{version}/…` as the prefix.  We strip exactly one leading
        // component so the result lands directly in `dest`.
        let stripped = raw_path
            .components()
            .skip(1)
            .collect::<PathBuf>();

        if stripped.as_os_str().is_empty() {
            // Top-level directory entry itself — skip it.
            continue;
        }

        let out_path = dest.join(&stripped);

        if file.header().entry_type().is_dir() {
            fs::create_dir_all(&out_path)
                .with_context(|| format!("mkdir {}", out_path.display()))?;
        } else {
            // Ensure parent exists
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("mkdir -p {}", parent.display()))?;
            }
            let mut out_file = fs::File::create(&out_path)
                .with_context(|| format!("create {}", out_path.display()))?;
            io::copy(&mut file, &mut out_file)
                .with_context(|| format!("write {}", out_path.display()))?;
        }
    }

    Ok(())
}

/// Regenerate `.cargo-checksum.json` for a crate directory.
///
/// The format is:
/// ```json
/// {"files":{"relative/path":"sha256hex",…},"package":null}
/// ```
fn write_cargo_checksum(crate_dir: &Path) -> Result<()> {
    let checksum_name = ".cargo-checksum.json";
    let mut files: BTreeMap<String, String> = BTreeMap::new();

    for entry in WalkDir::new(crate_dir).sort_by_file_name() {
        let entry = entry.context("walkdir error")?;
        if !entry.file_type().is_file() {
            continue;
        }
        let abs_path = entry.path();
        let rel = abs_path
            .strip_prefix(crate_dir)
            .unwrap_or(abs_path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        // Exclude the checksum file itself.
        if rel_str == checksum_name {
            continue;
        }

        let data = fs::read(abs_path)
            .with_context(|| format!("failed to read {}", abs_path.display()))?;
        files.insert(rel_str, sha256_hex(&data));
    }

    #[derive(Serialize)]
    struct CargoChecksum {
        files: BTreeMap<String, String>,
        package: Option<String>,
    }

    let checksum = CargoChecksum {
        files,
        package: None,
    };
    let json = serde_json::to_string(&checksum)?;

    let out = crate_dir.join(checksum_name);
    fs::write(&out, json.as_bytes())
        .with_context(|| format!("failed to write {}", out.display()))?;

    log::debug!("wrote {}", out.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Orphan cleanup
// ---------------------------------------------------------------------------

/// Remove directories under `registry_dir` that are not in the desired set
/// and not the `.takopack` metadata directory.
///
/// Returns the number of warnings emitted.
fn clean_orphans(
    registry_dir: &Path,
    current: &BTreeMap<String, ProviderEntry>,
) -> usize {
    let desired: HashSet<String> = current
        .values()
        .map(|e| e.registry_path.clone())
        .collect();

    let mut warnings = 0usize;

    let entries = match fs::read_dir(registry_dir) {
        Ok(e) => e,
        Err(_) => return 0, // directory may not exist yet
    };

    for dir_entry in entries {
        let dir_entry = match dir_entry {
            Ok(e) => e,
            Err(e) => {
                log::warn!("readdir error: {}", e);
                warnings += 1;
                continue;
            }
        };

        let name = dir_entry.file_name().to_string_lossy().to_string();
        if name == ".takopack" {
            continue;
        }

        if !dir_entry.path().is_dir() {
            continue;
        }

        if !desired.contains(&name) {
            log::info!("removing orphan directory: {}", name);
            if let Err(e) = fs::remove_dir_all(dir_entry.path()) {
                takopack_warn!("failed to remove orphan {}: {}", name, e);
                warnings += 1;
            }
        }
    }

    warnings
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hex digest of `data`.
fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex_encode(&hash)
}

/// Lower-case hex encoding (avoids pulling in `hex` crate).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_empty_index_roundtrip() {
        let idx = RegistryIndex::empty();
        let json = serde_json::to_string_pretty(&idx).unwrap();
        let parsed: RegistryIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, 1);
        assert!(parsed.entries.is_empty());
    }
}
