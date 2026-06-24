use std::collections::HashSet;

use log::{info, warn};

// Injection detection: read the game's /proc/<pid>/maps and evaluate executable mappings
// against both a path whitelist and a startup-baseline diff.
// Detection only reports; the ban decision is on the server (threat-model principle).
pub struct MapsScanner {
    pid: u32,
    allow_prefixes: Vec<String>,
    baseline: HashSet<String>,
    reported: HashSet<String>,
    initialized: bool,
}

// Standard system library paths. The game binary's dir is added at startup.
const SYSTEM_LIB_PREFIXES: &[&str] = &[
    "/usr/lib",
    "/lib",
    "/usr/lib64",
    "/lib64",
];

impl MapsScanner {
    pub fn new(pid: u32, game_binary: &str) -> Self {
        let mut allow_prefixes: Vec<String> =
            SYSTEM_LIB_PREFIXES.iter().map(|s| s.to_string()).collect();
        // Allow anything under the game binary's own directory
        if let Ok(canon) = std::fs::canonicalize(game_binary) {
            if let Some(dir) = canon.parent() {
                allow_prefixes.push(dir.to_string_lossy().into_owned());
            }
        }
        Self {
            pid,
            allow_prefixes,
            baseline: HashSet::new(),
            reported: HashSet::new(),
            initialized: false,
        }
    }

    // Whether an exec mapping's path is under the whitelist
    fn is_allowed_path(&self, path: &str) -> bool {
        self.allow_prefixes.iter().any(|p| path.starts_with(p.as_str()))
    }

    // Evaluate one line; return a reason if it looks like injection
    fn classify(&self, path: &str) -> Option<&'static str> {
        // Anonymous / special-region exec maps = traces of reflective injection / code generation
        if path.is_empty() {
            return Some("anonymous executable mapping");
        }
        if path.ends_with(" (deleted)") {
            return Some("deleted-file executable mapping");
        }
        if path.starts_with("/memfd:") || path.starts_with("/dev/shm/") {
            return Some("memfd/shm executable mapping");
        }
        if path.starts_with('[') {
            // [vdso], [vsyscall], etc. are kernel-provided and normal
            return None;
        }
        // file-backed: anything outside the whitelist is a suspicious .so
        if !self.is_allowed_path(path) {
            return Some("unexpected file-backed executable mapping");
        }
        None
    }

    pub fn scan(&mut self) {
        let content = match std::fs::read_to_string(format!("/proc/{}/maps", self.pid)) {
            Ok(c) => c,
            // Ignore process exit / transient read failures
            Err(_) => return,
        };

        for line in content.lines() {
            // address perms offset dev inode pathname
            let mut head = line.split_whitespace();
            let addr = head.next().unwrap_or("");
            let perms = head.next().unwrap_or("");
            if perms.as_bytes().get(2) != Some(&b'x') {
                continue; // executable maps only
            }
            // pathname is field 6 onward. Rejoin to preserve the space in " (deleted)"
            let path = line.split_whitespace().skip(5).collect::<Vec<_>>().join(" ");
            let path = path.as_str();

            // The startup scan only records the baseline
            if !self.initialized {
                self.baseline.insert(path.to_string());
                continue;
            }

            if let Some(reason) = self.classify(path) {
                // Anything already in the baseline is treated as normal (lazy loading, etc.)
                if self.baseline.contains(path) && !path.is_empty() {
                    continue;
                }
                // Suppress duplicate reports of the same map (keyed by addr+path)
                let key = format!("{addr} {path}");
                if self.reported.insert(key) {
                    warn!(
                        "INJECTION SUSPECT pid={} reason='{}' map='{}'",
                        self.pid,
                        reason,
                        if path.is_empty() { "<anon>" } else { path }
                    );
                }
            }
        }

        if !self.initialized {
            self.initialized = true;
            info!(
                "maps baseline recorded: {} exec mappings, {} allow-prefixes",
                self.baseline.len(),
                self.allow_prefixes.len()
            );
        }
    }
}
