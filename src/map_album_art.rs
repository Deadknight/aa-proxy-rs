use crate::config::AppConfig;
use log::{debug, warn};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::sync::{atomic::{AtomicU64, Ordering}, OnceLock, RwLock};
use std::time::Instant;

/// 1x1 transparent PNG used when no configured file or runtime art is available.
/// This keeps the metadata rewrite path deterministic without touching storage.
pub(crate) const BUILTIN_1X1_PNG: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, b'I', b'H', b'D', b'R',
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
    0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, b'I', b'D', b'A', b'T', 0x78, 0x9C, 0x63,
    0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00,
    0x00, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MapAlbumArtSource {
    File,
    Rest,
    Companion,
    RustH264,
}

impl MapAlbumArtSource {
    pub(crate) fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "rest" => Self::Rest,
            "companion" => Self::Companion,
            "rust_h264" | "h264" | "video" => Self::RustH264,
            "file" | "" => Self::File,
            other => {
                warn!(
                    "map album art: unknown source '{}'; falling back to file",
                    other
                );
                Self::File
            }
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Rest => "rest",
            Self::Companion => "companion",
            Self::RustH264 => "rust_h264",
        }
    }

    fn accepts_memory_source(self, source: &str) -> bool {
        match self {
            Self::File => false,
            // Companion currently posts PNGs through the same REST endpoint.
            Self::Rest | Self::Companion => matches!(source, "rest" | "companion"),
            Self::RustH264 => source == "rust_h264",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StoredAlbumArt {
    pub source: String,
    pub png: Vec<u8>,
    pub updated_at: Instant,
    pub version: u64,
}

pub(crate) struct LatestAlbumArtStore {
    latest: RwLock<Option<StoredAlbumArt>>,
    version: AtomicU64,
}

impl Default for LatestAlbumArtStore {
    fn default() -> Self {
        Self {
            latest: RwLock::new(None),
            version: AtomicU64::new(0),
        }
    }
}

impl LatestAlbumArtStore {
    pub(crate) fn set_png(&self, source: impl Into<String>, png: Vec<u8>) -> u64 {
        let version = self.version.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let mut latest = self.latest.write().expect("map album art store poisoned");
        *latest = Some(StoredAlbumArt {
            source: source.into(),
            png,
            updated_at: Instant::now(),
            version,
        });
        version
    }

    pub(crate) fn clear(&self) -> u64 {
        let version = self.version.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let mut latest = self.latest.write().expect("map album art store poisoned");
        *latest = None;
        version
    }

    pub(crate) fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    pub(crate) fn get(&self) -> Option<StoredAlbumArt> {
        self.latest
            .read()
            .expect("map album art store poisoned")
            .clone()
    }
}

static GLOBAL_STORE: OnceLock<LatestAlbumArtStore> = OnceLock::new();

pub(crate) fn global_album_art_store() -> &'static LatestAlbumArtStore {
    GLOBAL_STORE.get_or_init(LatestAlbumArtStore::default)
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedAlbumArt {
    pub source: String,
    pub png: Vec<u8>,
    /// Monotonic runtime artwork version. File/builtin fallbacks inherit the
    /// global store version so REST clear/upload can trigger a metadata refresh
    /// even when falling back to the configured file.
    pub version: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AlbumArtStatus {
    pub enabled: bool,
    pub source: String,
    pub max_bytes: usize,
    pub file: String,
    pub file_exists: bool,
    pub has_memory_art: bool,
    pub memory_source: Option<String>,
    pub memory_bytes: Option<usize>,
    pub memory_age_ms: Option<u128>,
    pub resolved_source: String,
    pub resolved_bytes: usize,
    pub store_version: u64,
}

pub(crate) fn is_png(data: &[u8]) -> bool {
    data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
}

pub(crate) fn validate_png(data: &[u8], max_bytes: usize) -> Result<(), String> {
    if data.is_empty() {
        return Err("PNG body is empty".to_string());
    }
    if data.len() > max_bytes {
        return Err(format!(
            "PNG is larger than map_album_art_max_bytes ({} > {})",
            data.len(), max_bytes
        ));
    }
    if !is_png(data) {
        return Err("Body is not a PNG; expected PNG signature".to_string());
    }
    Ok(())
}

fn read_file_png(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let data = fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    validate_png(&data, max_bytes)?;
    Ok(data)
}

pub(crate) fn resolve_album_art(cfg: &AppConfig) -> ResolvedAlbumArt {
    let source = MapAlbumArtSource::parse(&cfg.map_album_art_source);
    let store = global_album_art_store();
    let store_version = store.version();
    let fallback_version = if source == MapAlbumArtSource::File { 0 } else { store_version };

    if let Some(entry) = store.get() {
        if source.accepts_memory_source(&entry.source) {
            return ResolvedAlbumArt {
                source: entry.source,
                png: entry.png,
                version: entry.version,
            };
        }
    }

    match read_file_png(&cfg.map_album_art_file, cfg.map_album_art_max_bytes) {
        Ok(png) => ResolvedAlbumArt {
            source: "file".to_string(),
            png,
            version: fallback_version,
        },
        Err(e) => {
            debug!(
                "map album art: using built-in 1x1 PNG fallback; {}",
                e
            );
            ResolvedAlbumArt {
                source: "builtin_1x1".to_string(),
                png: BUILTIN_1X1_PNG.to_vec(),
                version: fallback_version,
            }
        }
    }
}

pub(crate) fn replacement_png_for_config(cfg: &AppConfig) -> ResolvedAlbumArt {
    let resolved = resolve_album_art(cfg);
    if resolved.png.len() > cfg.map_album_art_max_bytes {
        warn!(
            "map album art: resolved replacement from {} is larger than max bytes ({} > {}); using built-in fallback",
            resolved.source,
            resolved.png.len(),
            cfg.map_album_art_max_bytes
        );
        return ResolvedAlbumArt {
            source: "builtin_1x1".to_string(),
            png: BUILTIN_1X1_PNG.to_vec(),
            version: global_album_art_store().version(),
        };
    }
    resolved
}

pub(crate) fn status_for_config(cfg: &AppConfig) -> AlbumArtStatus {
    let memory = global_album_art_store().get();
    let resolved = resolve_album_art(cfg);

    AlbumArtStatus {
        enabled: cfg.map_album_art_enabled,
        source: MapAlbumArtSource::parse(&cfg.map_album_art_source)
            .as_str()
            .to_string(),
        max_bytes: cfg.map_album_art_max_bytes,
        file: cfg.map_album_art_file.display().to_string(),
        file_exists: cfg.map_album_art_file.exists(),
        has_memory_art: memory.is_some(),
        memory_source: memory.as_ref().map(|m| m.source.clone()),
        memory_bytes: memory.as_ref().map(|m| m.png.len()),
        memory_age_ms: memory
            .as_ref()
            .map(|m| m.updated_at.elapsed().as_millis()),
        resolved_source: resolved.source,
        resolved_bytes: resolved.png.len(),
        store_version: global_album_art_store().version(),
    }
}
