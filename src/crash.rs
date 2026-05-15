use chrono::Local;
use serde::Serialize;
use std::backtrace::Backtrace;
use std::fs::{self, File};
use std::io::Write;
use std::panic::{self, PanicHookInfo};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

const CRASH_FILE_PREFIX: &str = "panic_";
const CRASH_FILE_SUFFIX: &str = ".txt";

static CRASH_DIR: OnceLock<Arc<RwLock<PathBuf>>> = OnceLock::new();
static CRASH_HANDLER_ENABLED: OnceLock<Arc<AtomicBool>> = OnceLock::new();

#[derive(Debug, Serialize)]
pub struct CrashFileInfo {
    pub filename: String,
    pub path: String,
    pub size_bytes: u64,
    pub modified_unix_ms: Option<u64>,
}

pub fn install_panic_handler(initial_crash_dir: PathBuf, enabled: bool) {
    let dir = Arc::new(RwLock::new(initial_crash_dir));
    let _ = CRASH_DIR.set(dir);
    let _ = CRASH_HANDLER_ENABLED.set(Arc::new(AtomicBool::new(enabled)));

    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        write_panic_report(panic_info);
        previous_hook(panic_info);
    }));
}

pub fn set_crash_handler_enabled(enabled: bool) {
    if let Some(enabled_flag) = CRASH_HANDLER_ENABLED.get() {
        enabled_flag.store(enabled, Ordering::Relaxed);
    }
}

pub fn is_crash_handler_enabled() -> bool {
    CRASH_HANDLER_ENABLED
        .get()
        .map(|enabled_flag| enabled_flag.load(Ordering::Relaxed))
        .unwrap_or(true)
}

pub fn set_crash_dir(crash_dir: PathBuf) {
    if let Some(dir) = CRASH_DIR.get() {
        match dir.write() {
            Ok(mut guard) => *guard = crash_dir,
            Err(poisoned) => *poisoned.into_inner() = crash_dir,
        }
    }
}

pub fn current_crash_dir() -> PathBuf {
    CRASH_DIR
        .get()
        .map(|dir| match dir.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        })
        .unwrap_or_else(|| PathBuf::from(crate::config::DEFAULT_CRASH_DIR))
}

pub fn list_crashes(crash_dir: &Path) -> std::io::Result<Vec<CrashFileInfo>> {
    let mut files = Vec::new();

    if !crash_dir.exists() {
        return Ok(files);
    }

    for entry in fs::read_dir(crash_dir)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() || !is_crash_filename_path(&path) {
            continue;
        }

        let metadata = entry.metadata()?;
        let modified_unix_ms = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64);

        files.push(CrashFileInfo {
            filename: entry.file_name().to_string_lossy().into_owned(),
            path: path.display().to_string(),
            size_bytes: metadata.len(),
            modified_unix_ms,
        });
    }

    files.sort_by(|a, b| b.modified_unix_ms.cmp(&a.modified_unix_ms));
    Ok(files)
}

pub fn read_crash_file(crash_dir: &Path, filename: &str) -> std::io::Result<String> {
    if !is_safe_crash_filename(filename) {
        return Err(invalid_crash_filename_error());
    }

    fs::read_to_string(crash_dir.join(filename))
}

pub fn delete_crash_file(crash_dir: &Path, filename: &str) -> std::io::Result<()> {
    if !is_safe_crash_filename(filename) {
        return Err(invalid_crash_filename_error());
    }

    fs::remove_file(crash_dir.join(filename))
}

pub fn clear_crashes(crash_dir: &Path) -> std::io::Result<usize> {
    let files = list_crashes(crash_dir)?;
    let mut deleted = 0usize;

    for file in files {
        let path = crash_dir.join(&file.filename);
        match fs::remove_file(&path) {
            Ok(()) => deleted += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }

    Ok(deleted)
}

fn write_panic_report(panic_info: &PanicHookInfo<'_>) {
    if !is_crash_handler_enabled() {
        return;
    }

    let crash_dir = current_crash_dir();
    let _ = fs::create_dir_all(&crash_dir);

    let now = Local::now();
    let thread = std::thread::current();
    let thread_name = thread.name().unwrap_or("unnamed");
    let filename = format!(
        "{}{}_pid{}_thread{:?}{}",
        CRASH_FILE_PREFIX,
        now.format("%Y%m%d_%H%M%S_%3f"),
        process::id(),
        thread.id(),
        CRASH_FILE_SUFFIX
    );
    let path = crash_dir.join(filename);

    if let Ok(mut file) = File::create(path) {
        let _ = writeln!(file, "aa-proxy-rs panic report");
        let _ = writeln!(file, "time_local: {}", now.to_rfc3339());
        let _ = writeln!(file, "pid: {}", process::id());
        let _ = writeln!(file, "thread_name: {}", thread_name);
        let _ = writeln!(file, "thread_id: {:?}", thread.id());

        if let Some(location) = panic_info.location() {
            let _ = writeln!(
                file,
                "location: {}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            );
        } else {
            let _ = writeln!(file, "location: <unknown>");
        }

        let _ = writeln!(file, "panic: {}", panic_payload_to_string(panic_info));
        let _ = writeln!(file, "\nstacktrace:\n{}", Backtrace::force_capture());
    }
}

fn panic_payload_to_string(panic_info: &PanicHookInfo<'_>) -> String {
    if let Some(message) = panic_info.payload().downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = panic_info.payload().downcast_ref::<String>() {
        message.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

fn invalid_crash_filename_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "invalid crash filename",
    )
}

fn is_crash_filename_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(is_safe_crash_filename)
        .unwrap_or(false)
}

fn is_safe_crash_filename(filename: &str) -> bool {
    filename.starts_with(CRASH_FILE_PREFIX)
        && filename.ends_with(CRASH_FILE_SUFFIX)
        && !filename.contains('/')
        && !filename.contains('\\')
        && !filename.contains("..")
}
