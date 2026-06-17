use clap::{builder::styling::AnsiColor, builder::Styles, Parser, Subcommand, ValueEnum};

use crate::{
    package::{PackageExecuteArgs, PackageExtractArgs, PackageInitArgs},
    range_audit::RangeCapabilityPolicy,
    recursive_package::RecursivePackageArgs,
    repo_check::BuildReqsKind,
};

const CLI_STYLE: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default())
    .usage(AnsiColor::Green.on_default())
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Green.on_default());

#[derive(Debug, Clone, Parser)]
#[command(name = "takopack", about = "Package Rust crates for takopack")]
#[command(version)]
#[command(styles = CLI_STYLE)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Opt,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Opt {
    /// Rust/Cargo package operations
    #[command(subcommand)]
    Cargo(CargoOpt),
    /// Python package operations
    #[command(subcommand)]
    Py(PyOpt),
}

#[derive(Debug, Clone, Subcommand)]
pub enum CargoOpt {
    /// Update the crates.io index cache
    #[command(alias = "u")]
    Update,
    /// Package a single Rust crate and generate RPM spec file
    #[command(alias = "pkg")]
    Package {
        #[command(flatten)]
        init: PackageInitArgs,
        #[command(flatten)]
        extract: PackageExtractArgs,
        #[command(flatten)]
        finish: PackageExecuteArgs,
        /// Policy for range-capability warnings (warn|error|allow)
        #[arg(long, value_enum, default_value_t = RangeCapabilityPolicy::Warn)]
        range_capability_policy: RangeCapabilityPolicy,
    },
    /// Recursively package a crate and all its dependencies (vendor mode)
    #[command(alias = "v")]
    Vendor {
        #[command(flatten)]
        args: RecursivePackageArgs,
    },
    /// Parse Cargo.toml dependencies and recursively generate spec files for all
    #[command(name = "parsetoml", alias = "parse")]
    ParseToml {
        /// Path to Cargo.toml file
        #[arg(value_name = "CARGO_TOML")]
        toml_path: std::path::PathBuf,

        /// Output root directory. Each package is generated under this root.
        #[arg(short, long, value_name = "OUT_ROOT")]
        output: Option<std::path::PathBuf>,
    },
    /// Batch process multiple crates from a text file (one crate per line: "crate_name version")
    #[command(name = "batch")]
    Batch {
        /// Path to text file containing crate list (one per line: "name version")
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,

        /// Output root directory. Each package is generated under this root.
        #[arg(short, long, value_name = "OUT_ROOT")]
        output: Option<std::path::PathBuf>,
    },
    /// Package from a local crate directory (with Cargo.toml)
    #[command(name = "localpkg", alias = "local")]
    LocalPackage {
        /// Path to directory containing Cargo.toml (or path to Cargo.toml itself)
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,

        /// Final output package directory. Files are written directly into this directory.
        #[arg(
            short = 'o',
            long = "directory",
            alias = "output",
            value_name = "OUT_DIR"
        )]
        output: Option<std::path::PathBuf>,

        #[command(flatten)]
        finish: PackageExecuteArgs,

        /// Policy for range-capability warnings (warn|error|allow)
        #[arg(long, value_enum, default_value_t = RangeCapabilityPolicy::Warn)]
        range_capability_policy: RangeCapabilityPolicy,
    },
    /// Regenerate an existing provider while preserving source metadata
    #[command(name = "regen-provider", alias = "regenerate-provider")]
    RegenerateProvider {
        /// Existing provider directory containing Cargo.toml and a .spec file
        #[arg(value_name = "EXISTING_PROVIDER_DIR")]
        provider_dir: std::path::PathBuf,

        /// Output provider directory. Must not be the input directory.
        #[arg(
            short = 'o',
            long = "directory",
            alias = "output",
            value_name = "OUT_DIR"
        )]
        output: std::path::PathBuf,

        /// Optional base Cargo.toml used to generate the incremental Cargo.toml patch
        #[arg(long, value_name = "PATH")]
        base_cargo_toml: Option<std::path::PathBuf>,

        /// Policy for range-capability warnings (warn|error|allow)
        #[arg(long, value_enum, default_value_t = RangeCapabilityPolicy::Warn)]
        range_capability_policy: RangeCapabilityPolicy,
    },
    /// Generate RPM BuildRequires candidates from Cargo.toml
    #[command(name = "buildreqs")]
    BuildReqs {
        /// Input Cargo.toml
        #[arg(short = 'f', long, value_name = "CARGO_TOML")]
        file: std::path::PathBuf,

        /// Optional repo-index JSON for capability existence/version checks
        #[arg(long, value_name = "INDEX_JSON")]
        index: Option<std::path::PathBuf>,

        /// Package kind for policy defaults
        #[arg(long, value_enum, default_value = "crate")]
        kind: BuildReqsKind,

        /// Include [build-dependencies]
        #[arg(long, default_value_t = true)]
        include_build: bool,

        /// Include [dev-dependencies]
        #[arg(long)]
        include_dev: bool,

        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,

        /// Return non-zero when --index reports missing/conflict records
        #[arg(long)]
        check: bool,
    },
    /// Build a static crate capability index from RPM spec files
    #[command(name = "repo-index")]
    #[command(group(
        clap::ArgGroup::new("repo_source")
            .required(true)
            .multiple(true)
            .args(&["spec_repo_dir", "ruyispec"]),
    ))]
    RepoIndex {
        /// Directory containing generated Rust crate spec files
        #[arg(value_name = "SPEC_REPO_DIR")]
        spec_repo_dir: Option<std::path::PathBuf>,

        /// Use ruyispec.local_path from takopack.toml
        #[arg(long)]
        ruyispec: bool,

        /// Include every spec in packages, preserving the old broad scan behavior
        #[arg(long)]
        include_all_specs: bool,

        /// Output JSON index path
        #[arg(long, value_name = "INDEX_JSON")]
        output: std::path::PathBuf,
    },
    /// Check a Cargo.toml against a static repo capability index
    #[command(name = "repo-check")]
    RepoCheck {
        /// Application Cargo.toml to check
        #[arg(value_name = "CARGO_TOML")]
        cargo_toml: std::path::PathBuf,

        /// JSON index generated by repo-index
        #[arg(long, value_name = "INDEX_JSON")]
        index: std::path::PathBuf,

        /// Package kind for policy defaults
        #[arg(long, value_enum, default_value = "app")]
        kind: BuildReqsKind,

        /// Recursively check selected subpackage Requires
        #[arg(long)]
        check_transitive: bool,

        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Plan add/update/conflict actions from a Cargo.toml and repo index
    #[command(name = "repo-plan")]
    RepoPlan {
        /// Application Cargo.toml to plan from
        #[arg(value_name = "CARGO_TOML")]
        cargo_toml: std::path::PathBuf,

        /// JSON index generated by repo-index
        #[arg(long, value_name = "INDEX_JSON")]
        index: std::path::PathBuf,

        /// Package kind for policy defaults
        #[arg(long, value_enum, default_value = "app")]
        kind: BuildReqsKind,

        /// Recursively include selected subpackage Requires in the plan
        #[arg(long)]
        check_transitive: bool,

        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,

        /// Include full-repo warnings such as unrelated duplicate providers
        #[arg(long)]
        include_global_warnings: bool,
    },
    /// Report repository Rust crate migration and health issues
    #[command(name = "repo-health")]
    RepoHealth {
        /// JSON index generated by repo-index
        #[arg(long, value_name = "INDEX_JSON")]
        index: std::path::PathBuf,

        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Audit Rust application packages against a repo capability index
    #[command(name = "app-audit")]
    #[command(group(
        clap::ArgGroup::new("ruyispec_source")
            .required(true)
            .multiple(true)
            .args(&["ruyispec_dir", "ruyispec"]),
    ))]
    AppAudit {
        /// Local ruyispec repository directory
        #[arg(value_name = "RUYISPEC_DIR")]
        ruyispec_dir: Option<std::path::PathBuf>,

        /// Use ruyispec.local_path from takopack.toml
        #[arg(long)]
        ruyispec: bool,

        /// JSON index generated by repo-index
        #[arg(long, value_name = "INDEX_JSON")]
        index: std::path::PathBuf,

        /// Output audit report JSON path
        #[arg(long, value_name = "REPORT_JSON")]
        output: std::path::PathBuf,
    },
    /// Sync Rust crate providers from ruyispec to local Cargo directory registry
    #[command(name = "registry-sync")]
    RegistrySync {
        /// Only print the sync plan without making changes
        #[arg(long)]
        dry_run: bool,

        /// Number of concurrent crate downloads/extractions
        #[arg(short = 'j', long, default_value_t = 8, value_name = "N")]
        jobs: usize,
    },
    /// Check whether a Cargo.toml can resolve against the local TakoPack registry
    #[command(name = "resolve-check")]
    ResolveCheck {
        /// Path to a directory containing Cargo.toml, or a Cargo.toml file
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,

        /// Resolve against a temporary manifest with dev/test/bench dependencies removed
        #[arg(long)]
        no_dev: bool,

        /// Print BuildRequires candidates from the generated Cargo.lock on success
        #[arg(long)]
        print_buildrequires: bool,

        /// Temporarily fetch missing crates into an overlay registry to plan providers
        #[arg(long)]
        plan_missing: bool,

        /// Reuse a named plan overlay registry session
        #[arg(long, value_name = "NAME")]
        plan_session: Option<String>,

        /// Reset the named plan session before resolving
        #[arg(long)]
        plan_reset: bool,

        /// Add a crate/version to the plan overlay before resolving, e.g. crossterm@0.29.0
        #[arg(long, value_name = "CRATE@VERSION")]
        plan_add: Vec<String>,

        /// Try a same-compat provider upgrade in the plan overlay, e.g. serde_spanned@1.1.1
        #[arg(long, value_name = "CRATE@VERSION")]
        plan_upgrade: Vec<String>,

        /// Automatically apply same-compat upgrade candidates inside the plan overlay
        #[arg(long)]
        allow_session_upgrades: bool,

        /// Maximum plan-missing resolve iterations; 0 disables the fixed limit
        #[arg(long, default_value_t = 2000, value_name = "N")]
        max_plan_iterations: usize,

        /// Print plan progress every N iterations; 0 disables progress output
        #[arg(long, default_value_t = 100, value_name = "N")]
        plan_progress_interval: usize,

        /// Print the named plan session summary without resolving or modifying it
        #[arg(long)]
        plan_summary_only: bool,

        /// Storage mode for plan session registry initialization from baseline
        #[arg(long, value_enum, default_value_t = PlanSessionStorage::Auto, value_name = "MODE")]
        plan_session_storage: PlanSessionStorage,
    },
    /// Track dependencies from a crate and generate action list
    #[command(name = "track")]
    #[command(group(
        clap::ArgGroup::new("source")
            .required(true)
            .args(&["crate_name", "from_file"]),
    ))]
    Track {
        /// Crate name
        #[arg(value_name = "CRATE")]
        crate_name: Option<String>,

        /// Crate version (optional, uses latest if not specified)
        #[arg(value_name = "VERSION")]
        version: Option<String>,

        /// Path to Cargo.toml or Cargo.lock file
        #[arg(short = 'f', long, value_name = "FILE")]
        from_file: Option<std::path::PathBuf>,

        /// Output directory for generated specs (default: track_TIMESTAMP/)
        #[arg(short = 'o', long, value_name = "DIR")]
        output: Option<std::path::PathBuf>,

        /// Database file (default: ~/.config/takopack/crate_db.txt)
        #[arg(long, value_name = "FILE")]
        database: Option<std::path::PathBuf>,

        /// Output file for crates that need action (default: needs_action.txt)
        #[arg(long, value_name = "FILE")]
        action_file: Option<std::path::PathBuf>,
    },
    /// Audit Cargo.toml dependencies for range requirements that span multiple RPM compat keys
    #[command(name = "range-audit")]
    RangeAudit {
        /// Path to a Cargo.toml file, crate directory, or workspace directory
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,

        /// Exit non-zero if any warnings are found
        #[arg(long)]
        strict: bool,

        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
}

/// Storage mode for plan session registry creation.
///
/// Controls how the baseline cargo registry is copied into a plan session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PlanSessionStorage {
    /// Try fuse-overlay first, then reflink, then copy. Never hardlink.
    Auto,
    /// Use fuse-overlayfs to mount baseline as read-only lower layer.
    #[value(name = "fuse-overlay")]
    FuseOverlay,
    /// Use reflink (CoW) copy. Fail if the filesystem does not support it.
    Reflink,
    /// Regular recursive copy. Slowest but safest.
    Copy,
    /// Hard-link files from baseline. Fast but session edits can pollute baseline.
    Hardlink,
}

impl std::fmt::Display for PlanSessionStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanSessionStorage::Auto => write!(f, "auto"),
            PlanSessionStorage::FuseOverlay => write!(f, "fuse-overlay"),
            PlanSessionStorage::Reflink => write!(f, "reflink"),
            PlanSessionStorage::Copy => write!(f, "copy"),
            PlanSessionStorage::Hardlink => write!(f, "hardlink"),
        }
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum PyOpt {
    /// Package a Python package from PyPI and generate RPM spec file
    #[command(alias = "pkg")]
    Package {
        /// PyPI package name
        #[arg(value_name = "NAME")]
        name: String,

        /// Package version (optional, latest if omitted)
        #[arg(value_name = "VERSION")]
        version: Option<String>,

        /// Output directory for generated spec folder (default: current directory)
        #[arg(short, long, value_name = "DIR")]
        output: Option<std::path::PathBuf>,
    },
}
