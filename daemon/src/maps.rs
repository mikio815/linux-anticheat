use std::collections::HashSet;

use log::{info, warn};

// 注入検出: ゲームの /proc/<pid>/maps を読み、実行可能マッピングを
// パスホワイトリスト + 起動時ベースライン差分の両方で評価する (両方併用)。
// 検出は report のみ。ban 判断はサーバー側 (脅威モデルの原則)。
pub struct MapsScanner {
    pid: u32,
    allow_prefixes: Vec<String>,
    baseline: HashSet<String>,
    reported: HashSet<String>,
    initialized: bool,
}

// system のライブラリ標準パス。ゲームバイナリの dir は起動時に追加する。
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
        // ゲームバイナリと同じディレクトリ配下を許可
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

    // exec マッピングのパスがホワイトリスト配下か
    fn is_allowed_path(&self, path: &str) -> bool {
        self.allow_prefixes.iter().any(|p| path.starts_with(p.as_str()))
    }

    // 1 行を評価し、注入の疑いがあれば理由を返す
    fn classify(&self, path: &str) -> Option<&'static str> {
        // 匿名 / 特殊領域の実行マップ = reflective injection / コード生成の痕跡
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
            // [vdso] [vsyscall] 等はカーネル提供で正常
            return None;
        }
        // file-backed: ホワイトリスト外は不審な .so
        if !self.is_allowed_path(path) {
            return Some("unexpected file-backed executable mapping");
        }
        None
    }

    pub fn scan(&mut self) {
        let content = match std::fs::read_to_string(format!("/proc/{}/maps", self.pid)) {
            Ok(c) => c,
            // プロセス終了 / 一時的な読み取り不可は無視
            Err(_) => return,
        };

        for line in content.lines() {
            // address perms offset dev inode pathname
            let mut head = line.split_whitespace();
            let addr = head.next().unwrap_or("");
            let perms = head.next().unwrap_or("");
            if perms.as_bytes().get(2) != Some(&b'x') {
                continue; // 実行可能マップのみ対象
            }
            // pathname は 6 フィールド目以降。" (deleted)" の空白を保つため join で再構成
            let path = line.split_whitespace().skip(5).collect::<Vec<_>>().join(" ");
            let path = path.as_str();

            // 起動時スキャンはベースラインとして記録するだけ
            if !self.initialized {
                self.baseline.insert(path.to_string());
                continue;
            }

            if let Some(reason) = self.classify(path) {
                // ベースラインに在ったものは正常 (遅延ロード等) として許容
                if self.baseline.contains(path) && !path.is_empty() {
                    continue;
                }
                // 同一マップの重複報告を抑制 (addr+path をキー)
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
