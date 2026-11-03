use anyhow::{Result, anyhow};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

pub const DEFAULT_RUN_DIR: &str = "/run/dflux";
pub const DEFAULT_LOCK_FILE: &str = "/run/dflux/dflux.lock";
pub const DEFAULT_STATE_FILE: &str = "/run/dflux/state.json";

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeploymentState {
    pub uuid: String,
    pub pid: u32,
    pub created_at: u64,
    pub table_name: String,
    pub rule_pref: u32,
    pub fwmark: u32,
    pub table_id: u32,
    pub nft_active: bool,
    pub ip_rule_active: bool,
    pub ip_route_active: bool,
}

/// Manages routing rules using nftables and policy routing with strict concurrency control,
/// pre-validation, verified resource ownership, and conservative teardown.
pub struct RoutingEngine {
    port: u16,
    direct_iface: String,
    remote_iface: Option<String>,
    exclude_subnets: String,
    run_dir: PathBuf,
    lock_fd: Option<RawFd>,
    created_nft: AtomicBool,
    created_rule: AtomicBool,
    created_route: AtomicBool,
}

impl RoutingEngine {
    pub fn new(
        port: u16,
        direct_iface: String,
        remote_iface: Option<String>,
        exclude_subnets: String,
    ) -> Self {
        Self::new_with_run_dir(
            port,
            direct_iface,
            remote_iface,
            exclude_subnets,
            PathBuf::from(DEFAULT_RUN_DIR),
        )
    }

    pub fn new_with_run_dir(
        port: u16,
        direct_iface: String,
        remote_iface: Option<String>,
        exclude_subnets: String,
        run_dir: PathBuf,
    ) -> Self {
        Self {
            port,
            direct_iface,
            remote_iface,
            exclude_subnets,
            run_dir,
            lock_fd: None,
            created_nft: AtomicBool::new(false),
            created_rule: AtomicBool::new(false),
            created_route: AtomicBool::new(false),
        }
    }

    /// Sets up transparent proxy rules using nftables TPROXY with pre-validation and rollback tracking.
    pub fn start(&mut self) -> Result<()> {
        if self.direct_iface.trim().is_empty()
            || !Path::new("/sys/class/net")
                .join(&self.direct_iface)
                .exists()
        {
            return Err(anyhow!(
                "DIRECT interface '{}' does not exist",
                self.direct_iface
            ));
        }
        if let Some(remote) = &self.remote_iface
            && (remote.trim().is_empty() || !Path::new("/sys/class/net").join(remote).exists())
        {
            return Err(anyhow!("REMOTE interface '{}' does not exist", remote));
        }
        println!("Starting Routing Engine (nftables TPROXY)...");

        // 1. Acquire exclusive lockfile in protected directory
        self.acquire_lock()?;

        // 2. Pre-inspection: Check for conflicting pre-existing resources
        self.check_preexisting_conflicts()?;

        // 3. Initialize deployment state tracking. TPROXY terminates connections locally, so
        // forwarding and broad postrouting NAT are not needed and are deliberately untouched.
        let uuid = format!(
            "{:016x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let mut state = DeploymentState {
            uuid,
            pid: std::process::id(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            table_name: "dflux".to_string(),
            rule_pref: 32000,
            fwmark: 1,
            table_id: 100,
            nft_active: false,
            ip_rule_active: false,
            ip_route_active: false,
        };

        // 5. Step 1: Apply nftables table
        let rules = format!(
            "table ip dflux {{\n    chain prerouting {{\n        type filter hook prerouting priority mangle; policy accept;\n        ip daddr {{ {exclude_subnets} }} accept\n        tcp dport {{ 80, 443 }} tproxy to :{port} meta mark set 1 accept\n    }}\n    chain output_route {{\n        type route hook output priority mangle; policy accept;\n        meta mark 0x4446 accept\n        ip daddr {{ {exclude_subnets} }} accept\n    }}\n    chain output_nat {{\n        type nat hook output priority dstnat; policy accept;\n        meta mark 0x4446 return\n        ip daddr {{ {exclude_subnets} }} return\n        tcp dport {{ 80, 443 }} redirect to :{port}\n    }}\n}}\ntable ip6 dflux6 {{\n    chain prerouting {{ type filter hook prerouting priority mangle; policy accept; tcp dport {{ 80, 443 }} reject; }}\n    chain output {{ type filter hook output priority mangle; policy accept; tcp dport {{ 80, 443 }} reject; }}\n}}",
            port = self.port,
            exclude_subnets = self.exclude_subnets,
        );

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(rules.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _ = self.stop();
            return Err(anyhow!("Failed to apply nftables rules: {}", stderr.trim()));
        }

        self.created_nft.store(true, Ordering::SeqCst);
        state.nft_active = true;
        self.save_state_atomic(&state)?;

        // 6. Step 2: Add policy routing rule with pref 32000
        if let Err(e) = Self::run_cmd_checked(
            Command::new("ip").args([
                "rule", "add", "fwmark", "1", "lookup", "100", "pref", "32000",
            ]),
            "Add policy routing rule (pref 32000)",
        ) {
            let _ = self.stop();
            return Err(e);
        }

        self.created_rule.store(true, Ordering::SeqCst);
        state.ip_rule_active = true;
        self.save_state_atomic(&state)?;

        // 7. Step 3: Add local route in table 100
        if let Err(e) = Self::run_cmd_checked(
            Command::new("ip").args([
                "route",
                "add",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                "100",
            ]),
            "Add local route in table 100",
        ) {
            let _ = self.stop();
            return Err(e);
        }

        self.created_route.store(true, Ordering::SeqCst);
        state.ip_route_active = true;
        self.save_state_atomic(&state)?;

        println!("Routing Engine rules applied successfully.");
        Ok(())
    }

    /// Conservatively rolls back network resources created by DFlux.
    /// Order: (1) Verify ownership, (2) Flush/delete nftables table, (3) Delete ip rule,
    /// (4) Delete local route, (5) Update state and remove state file when complete.
    pub fn stop(&self) -> Result<()> {
        println!("Stopping Routing Engine and reverting changes...");
        let state_file = self.run_dir.join("state.json");
        let mut loaded_state = Self::read_state_file(&state_file).ok();

        // Step 1: Remove nftables table ip dflux
        let should_remove_nft = self.created_nft.load(Ordering::SeqCst)
            || loaded_state.as_ref().is_some_and(|s| s.nft_active);

        if should_remove_nft && Self::verify_nft_ownership()? {
            let res = Self::run_cmd_checked(
                Command::new("nft").args(["delete", "table", "ip", "dflux"]),
                "Delete nftables table ip dflux",
            );
            let v6_res = if Self::verify_nft6_ownership()? {
                Self::run_cmd_checked(
                    Command::new("nft").args(["delete", "table", "ip6", "dflux6"]),
                    "Delete nftables table ip6 dflux6",
                )
            } else {
                Ok(String::new())
            };
            if res.is_ok() && v6_res.is_ok() {
                self.created_nft.store(false, Ordering::SeqCst);
                if let Some(ref mut st) = loaded_state {
                    st.nft_active = false;
                    let _ = Self::save_state_to_path(&state_file, st);
                }
            }
        }

        // Step 2: Remove ip rule pref 32000
        let should_remove_rule = self.created_rule.load(Ordering::SeqCst)
            || loaded_state.as_ref().is_some_and(|s| s.ip_rule_active);

        if should_remove_rule && Self::verify_ip_rule_ownership()? {
            let res = Self::run_cmd_checked(
                Command::new("ip").args([
                    "rule", "del", "pref", "32000", "fwmark", "1", "lookup", "100",
                ]),
                "Delete ip rule (pref 32000)",
            );
            if res.is_ok() {
                self.created_rule.store(false, Ordering::SeqCst);
                if let Some(ref mut st) = loaded_state {
                    st.ip_rule_active = false;
                    let _ = Self::save_state_to_path(&state_file, st);
                }
            }
        }

        // Step 3: Remove ip route in table 100
        let should_remove_route = self.created_route.load(Ordering::SeqCst)
            || loaded_state.as_ref().is_some_and(|s| s.ip_route_active);

        if should_remove_route && Self::verify_ip_route_ownership()? {
            let res = Self::run_cmd_checked(
                Command::new("ip").args([
                    "route",
                    "del",
                    "local",
                    "0.0.0.0/0",
                    "dev",
                    "lo",
                    "table",
                    "100",
                ]),
                "Delete ip route in table 100",
            );
            if res.is_ok() {
                self.created_route.store(false, Ordering::SeqCst);
                if let Some(ref mut st) = loaded_state {
                    st.ip_route_active = false;
                    let _ = Self::save_state_to_path(&state_file, st);
                }
            }
        }

        // Step 4: If all resources are verified cleaned, remove state.json
        if let Some(ref st) = loaded_state
            && !st.nft_active
            && !st.ip_rule_active
            && !st.ip_route_active
        {
            let _ = fs::remove_file(&state_file);
        }

        println!("Routing Engine stopped.");
        Ok(())
    }

    /// Acquires an exclusive file lock on /run/dflux/dflux.lock to prevent concurrent instances.
    /// The lockfile is NEVER unlinked on completion to avoid race conditions.
    fn acquire_lock(&mut self) -> Result<()> {
        use std::os::fd::FromRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        if !self.run_dir.exists() {
            let _ = fs::create_dir_all(&self.run_dir);
            let _ = fs::set_permissions(&self.run_dir, fs::Permissions::from_mode(0o700));
        }

        let dir_path = std::ffi::CString::new(self.run_dir.as_os_str().as_bytes())?;
        let dir_fd = unsafe {
            libc::open(
                dir_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if dir_fd < 0 {
            return Err(anyhow!(
                "Failed to securely open routing state directory: {}",
                std::io::Error::last_os_error()
            ));
        }
        let dir = unsafe { std::fs::File::from_raw_fd(dir_fd) };
        let dir_meta = dir.metadata()?;
        if !dir_meta.file_type().is_dir()
            || dir_meta.uid() != 0
            || (dir_meta.mode() & 0o777) != 0o700
        {
            return Err(anyhow!(
                "Routing state directory must be a root-owned real directory with mode 0700"
            ));
        }
        let lock_fd = open_lockfile_at(dir.as_raw_fd());
        if lock_fd < 0 {
            return Err(anyhow!(
                "Failed to securely open lockfile relative to routing directory: {}",
                std::io::Error::last_os_error()
            ));
        }
        let file = unsafe { std::fs::File::from_raw_fd(lock_fd) };

        let fd = file.as_raw_fd();
        let meta = file.metadata()?;
        if !meta.file_type().is_file() || meta.uid() != 0 || (meta.mode() & 0o777) & 0o077 != 0 {
            return Err(anyhow!(
                "Routing lockfile must be a root-owned regular file with restrictive permissions"
            ));
        }
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            return Err(anyhow!(
                "Another instance of DFlux is currently active (lockfile held in {:?})",
                self.run_dir
            ));
        }

        // Store open RawFd so it remains held for the lifetime of RoutingEngine
        std::mem::forget(file);
        self.lock_fd = Some(fd);
        Ok(())
    }

    /// Pre-installation check: aborts if conflicting network resources already exist.
    fn check_preexisting_conflicts(&self) -> Result<()> {
        let state_path = self.run_dir.join("state.json");
        if state_path.exists()
            && let Ok(state) = Self::read_state_file(&state_path)
        {
            // Check if the process recorded in state is still alive
            let is_alive = unsafe { libc::kill(state.pid as libc::pid_t, 0) == 0 };
            if is_alive {
                return Err(anyhow!(
                    "DFlux instance (PID {}) is already running with active state file",
                    state.pid
                ));
            }
        }

        // Check nftables table
        if let Ok(output) = Command::new("nft")
            .args(["list", "table", "ip", "dflux"])
            .output()
            && output.status.success()
        {
            return Err(anyhow!(
                "Conflict detected: nftables table 'ip dflux' already exists on the system"
            ));
        }

        if let Ok(output) = Command::new("nft")
            .args(["list", "table", "ip6", "dflux6"])
            .output()
            && output.status.success()
        {
            return Err(anyhow!(
                "Conflict detected: nftables table 'ip6 dflux6' already exists on the system"
            ));
        }

        // Check ip rule pref 32000
        if let Ok(output) = Command::new("ip")
            .args(["rule", "show", "pref", "32000"])
            .output()
        {
            let out_str = String::from_utf8_lossy(&output.stdout);
            if !out_str.trim().is_empty() {
                return Err(anyhow!(
                    "Conflict detected: ip rule at pref 32000 already exists: '{}'",
                    out_str.trim()
                ));
            }
        }

        // Check ip route in table 100
        if let Ok(output) = Command::new("ip")
            .args(["route", "show", "table", "100"])
            .output()
        {
            let out_str = String::from_utf8_lossy(&output.stdout);
            if !out_str.trim().is_empty() {
                return Err(anyhow!(
                    "Conflict detected: routing table 100 already contains routes: '{}'",
                    out_str.trim()
                ));
            }
        }

        Ok(())
    }

    /// Verifies that table ip dflux belongs to DFlux and does not contain arbitrary third-party chains.
    pub fn verify_nft_ownership() -> Result<bool> {
        let output = Command::new("nft")
            .args(["list", "table", "ip", "dflux"])
            .output()?;
        if !output.status.success() {
            return Ok(false); // Table doesn't exist
        }
        let out_str = String::from_utf8_lossy(&output.stdout);
        // Table must contain dflux markers
        if out_str.contains("0x4446") || out_str.contains("tproxy to") {
            Ok(true)
        } else {
            eprintln!("Refusing to delete 'table ip dflux': table does not match DFlux signature");
            Ok(false)
        }
    }

    pub fn verify_nft6_ownership() -> Result<bool> {
        let output = Command::new("nft")
            .args(["list", "table", "ip6", "dflux6"])
            .output()?;
        if !output.status.success() {
            return Ok(false);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains("reject") && text.contains("dflux6") {
            Ok(true)
        } else {
            eprintln!(
                "Refusing to delete 'table ip6 dflux6': table does not match DFlux signature"
            );
            Ok(false)
        }
    }

    /// Verifies that ip rule pref 32000 matches DFlux parameters exactly.
    pub fn verify_ip_rule_ownership() -> Result<bool> {
        let output = Command::new("ip")
            .args(["rule", "show", "pref", "32000"])
            .output()?;
        if !output.status.success() {
            return Ok(false);
        }
        let out_str = String::from_utf8_lossy(&output.stdout);
        if out_str.contains("fwmark 0x1 lookup 100") || out_str.contains("fwmark 1 lookup 100") {
            Ok(true)
        } else {
            eprintln!(
                "Refusing to delete ip rule at pref 32000: parameters do not match DFlux ('{}')",
                out_str.trim()
            );
            Ok(false)
        }
    }

    /// Verifies that table 100 route matches DFlux parameters.
    pub fn verify_ip_route_ownership() -> Result<bool> {
        let output = Command::new("ip")
            .args(["route", "show", "table", "100"])
            .output()?;
        if !output.status.success() {
            return Ok(false);
        }
        let out_str = String::from_utf8_lossy(&output.stdout);
        if out_str.contains("local default dev lo") || out_str.contains("local 0.0.0.0/0 dev lo") {
            Ok(true)
        } else {
            eprintln!(
                "Refusing to delete route in table 100: route does not match DFlux ('{}')",
                out_str.trim()
            );
            Ok(false)
        }
    }

    /// Executes a command and verifies that status.success() is true.
    pub fn run_cmd_checked(cmd: &mut Command, desc: &str) -> Result<String> {
        let output = cmd
            .output()
            .map_err(|e| anyhow!("Failed to execute command for {}: {}", desc, e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "{} failed with exit code {:?}: {}",
                desc,
                output.status.code(),
                stderr.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Atomically writes state to /run/dflux/state.json using a temporary file and rename().
    fn save_state_atomic(&self, state: &DeploymentState) -> Result<()> {
        let state_path = self.run_dir.join("state.json");
        Self::save_state_to_path(&state_path, state)
    }

    pub fn save_state_to_path(state_path: &Path, state: &DeploymentState) -> Result<()> {
        let parent = state_path
            .parent()
            .ok_or_else(|| anyhow!("Invalid state path"))?;
        fs::create_dir_all(parent)?;

        let tmp_path = parent.join(format!("state.json.tmp.{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;

        let json = serde_json::to_string_pretty(state)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        drop(file);

        fs::rename(&tmp_path, state_path)?;
        Ok(())
    }

    pub fn read_state_file(path: &Path) -> Result<DeploymentState> {
        let content = fs::read_to_string(path)?;
        let state: DeploymentState = serde_json::from_str(&content)?;
        Ok(state)
    }
}

/// Opens the fixed lock filename relative to the already validated directory descriptor.
fn open_lockfile_at(dir_fd: RawFd) -> RawFd {
    let lock_name = std::ffi::CString::new("dflux.lock").expect("static lock filename");
    unsafe {
        libc::openat(
            dir_fd,
            lock_name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    }
}

impl Drop for RoutingEngine {
    fn drop(&mut self) {
        if self.created_nft.load(Ordering::SeqCst)
            || self.created_rule.load(Ordering::SeqCst)
            || self.created_route.load(Ordering::SeqCst)
        {
            let _ = self.stop();
        }
        if let Some(fd) = self.lock_fd.take() {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

#[cfg(test)]
mod lockfile_tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dflux-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn engine(dir: &Path) -> RoutingEngine {
        RoutingEngine::new_with_run_dir(12345, "lo".into(), None, "127.0.0.0/8".into(), dir.into())
    }

    #[test]
    fn lock_creation_stays_relative_to_validated_open_directory() {
        let root = temp_root("openat");
        let original = root.join("run");
        fs::create_dir_all(&original).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let cpath = std::ffi::CString::new(original.as_os_str().as_bytes()).unwrap();
        let dirfd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        assert!(dirfd >= 0);
        fs::rename(&original, root.join("moved")).unwrap();
        fs::create_dir(&original).unwrap();
        let replacement_lock = original.join("dflux.lock");
        fs::write(&replacement_lock, b"attacker path").unwrap();
        let fd = open_lockfile_at(dirfd);
        assert!(fd >= 0);
        let opened = unsafe { std::fs::File::from_raw_fd(fd) };
        let moved_meta = fs::metadata(root.join("moved/dflux.lock")).unwrap();
        assert_eq!(opened.metadata().unwrap().ino(), moved_meta.ino());
        assert_ne!(
            opened.metadata().unwrap().ino(),
            fs::metadata(replacement_lock).unwrap().ino()
        );
        unsafe {
            libc::close(dirfd);
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// Run explicitly as root with `cargo test lockfile_root_security_matrix -- --ignored`.
    #[test]
    #[ignore = "requires root ownership and permission changes"]
    fn lockfile_root_security_matrix() {
        let root = temp_root("lock-matrix");
        fs::create_dir_all(&root).unwrap();

        let valid = root.join("valid");
        fs::create_dir(&valid).unwrap();
        fs::set_permissions(&valid, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            engine(&valid).acquire_lock().is_ok(),
            "root-owned 0700 directory and regular 0600 lock are accepted"
        );

        let symlink_target = root.join("target");
        fs::create_dir(&symlink_target).unwrap();
        let symlink_dir = root.join("symlink-dir");
        std::os::unix::fs::symlink(&symlink_target, &symlink_dir).unwrap();
        assert!(engine(&symlink_dir).acquire_lock().is_err());

        let wrong_owner = root.join("wrong-owner");
        fs::create_dir(&wrong_owner).unwrap();
        fs::set_permissions(&wrong_owner, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            std::process::Command::new("chown")
                .args(["65534:65534", wrong_owner.to_str().unwrap()])
                .status()
                .unwrap()
                .success()
        );
        assert!(engine(&wrong_owner).acquire_lock().is_err());

        let wrong_mode = root.join("wrong-mode");
        fs::create_dir(&wrong_mode).unwrap();
        fs::set_permissions(&wrong_mode, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(engine(&wrong_mode).acquire_lock().is_err());

        let valid_file = root.join("valid-file");
        fs::create_dir(&valid_file).unwrap();
        fs::set_permissions(&valid_file, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(valid_file.join("dflux.lock"), b"").unwrap();
        fs::set_permissions(
            valid_file.join("dflux.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(engine(&valid_file).acquire_lock().is_ok());

        let symlink_file = root.join("symlink-file");
        fs::create_dir(&symlink_file).unwrap();
        fs::set_permissions(&symlink_file, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("lock-target"), b"").unwrap();
        std::os::unix::fs::symlink(root.join("lock-target"), symlink_file.join("dflux.lock"))
            .unwrap();
        assert!(engine(&symlink_file).acquire_lock().is_err());

        let wrong_file_owner = root.join("wrong-file-owner");
        fs::create_dir(&wrong_file_owner).unwrap();
        fs::set_permissions(&wrong_file_owner, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(wrong_file_owner.join("dflux.lock"), b"").unwrap();
        fs::set_permissions(
            wrong_file_owner.join("dflux.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(
            std::process::Command::new("chown")
                .args([
                    "65534:65534",
                    wrong_file_owner.join("dflux.lock").to_str().unwrap()
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(engine(&wrong_file_owner).acquire_lock().is_err());

        let wrong_type = root.join("wrong-type");
        fs::create_dir(&wrong_type).unwrap();
        fs::set_permissions(&wrong_type, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(wrong_type.join("dflux.lock")).unwrap();
        assert!(engine(&wrong_type).acquire_lock().is_err());

        let mut held = engine(&valid);
        held.acquire_lock().unwrap();
        let contender = std::process::Command::new("python3")
            .arg("-c")
            .arg("import fcntl,os,sys; f=os.open(sys.argv[1],os.O_RDWR);\ntry: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(0)\nsys.exit(1)")
            .arg(valid.join("dflux.lock")).status().unwrap();
        assert_eq!(
            contender.code(),
            Some(0),
            "a second process cannot acquire the held lock"
        );
        drop(held);
        fs::remove_dir_all(root).unwrap();
    }
}
