use crate::config::AppConfig;
use crate::map_album_art::{global_album_art_store, validate_png, MapAlbumArtSource};
use log::{debug, info, warn};
use rust_h264::decoder::{Decoder, Frame};
use rust_h264::nal::parse_annex_b;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const MEDIA_MESSAGE_CODEC_CONFIG: u16 = 0x0001;
const MEDIA_MESSAGE_DATA: u16 = 0x0000;
const RUST_H264_SOURCE: &str = "rust_h264";
const DEFAULT_OUTPUT_SIZE: u32 = 256;
const MIN_OUTPUT_SIZE: u32 = 32;
const MAX_OUTPUT_SIZE: u32 = 1024;

#[derive(Clone, Debug)]
struct H264ArtOptions {
    capture_interval_ms: u64,
    output_size_px: u32,
    crop_x_percent: u8,
    crop_y_percent: u8,
    crop_w_percent: u8,
    crop_h_percent: u8,
    max_bytes: usize,
}

impl H264ArtOptions {
    fn from_config(cfg: &AppConfig) -> Self {
        Self {
            capture_interval_ms: cfg.map_album_art_capture_interval_ms,
            output_size_px: clamp_output_size(cfg.map_album_art_output_size_px),
            crop_x_percent: cfg.map_album_art_crop_x_percent.min(100),
            crop_y_percent: cfg.map_album_art_crop_y_percent.min(100),
            crop_w_percent: cfg.map_album_art_crop_w_percent.min(100),
            crop_h_percent: cfg.map_album_art_crop_h_percent.min(100),
            max_bytes: cfg.map_album_art_max_bytes,
        }
    }
}

#[derive(Debug)]
enum H264ArtCommand {
    CodecConfig { data: Vec<u8> },
    VideoFrame { data: Vec<u8>, options: H264ArtOptions },
}

static H264_ART_TX: OnceLock<Sender<H264ArtCommand>> = OnceLock::new();

fn h264_art_tx() -> &'static Sender<H264ArtCommand> {
    H264_ART_TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<H264ArtCommand>();
        std::thread::Builder::new()
            .name("map-album-art-h264".to_string())
            .spawn(move || h264_worker(rx))
            .expect("failed to spawn map album art h264 worker");
        tx
    })
}

pub(crate) fn target_display_id<'a>(cfg: &'a AppConfig) -> Option<&'a str> {
    if !cfg.map_album_art_enabled
        || MapAlbumArtSource::parse(&cfg.map_album_art_source) != MapAlbumArtSource::RustH264
    {
        return None;
    }

    let id = cfg.map_album_art_video_display_id.trim();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

pub(crate) fn is_active(cfg: &AppConfig) -> bool {
    target_display_id(cfg).is_some()
}

pub(crate) fn maybe_feed_media_frame(
    cfg: &AppConfig,
    channel: u8,
    inject_display_id: Option<&str>,
    frame_data: &[u8],
) {
    if !is_active(cfg) {
        return;
    }

    let target_display_id = cfg.map_album_art_video_display_id.trim();

    let Some(inject_display_id) = inject_display_id else {
        return;
    };

    if inject_display_id != target_display_id {
        return;
    }

    if frame_data.len() < 2 {
        return;
    }

    let message_id = u16::from_be_bytes([frame_data[0], frame_data[1]]);
    match message_id {
        MEDIA_MESSAGE_CODEC_CONFIG => {
            let codec_data = &frame_data[2..];
            if codec_data.is_empty() {
                return;
            }
            if h264_art_tx()
                .send(H264ArtCommand::CodecConfig {
                    data: codec_data.to_vec(),
                })
                .is_ok()
            {
                info!(
                    "map album art h264: queued codec config from display={} ch={:#04x} ({} bytes)",
                    inject_display_id,
                    channel,
                    codec_data.len()
                );
            }
        }
        MEDIA_MESSAGE_DATA => {
            const TIMESTAMP_HEADER: usize = 8;
            let payload = &frame_data[2..];
            if payload.len() <= TIMESTAMP_HEADER {
                return;
            }
            let media_data = &payload[TIMESTAMP_HEADER..];
            if !contains_idr_nal(media_data) {
                return;
            }
            let options = H264ArtOptions::from_config(cfg);
            if h264_art_tx()
                .send(H264ArtCommand::VideoFrame {
                    data: media_data.to_vec(),
                    options,
                })
                .is_ok()
            {
                info!(
                    "map album art h264: queued IDR frame from display={} ch={:#04x} ({} bytes)",
                    inject_display_id,
                    channel,
                    media_data.len()
                );
            }
        }
        _ => {}
    }
}

fn h264_worker(rx: Receiver<H264ArtCommand>) {
    let mut codec_config: Option<Vec<u8>> = None;
    let mut last_emit_at: Option<Instant> = None;
    let mut last_warn_at: Option<Instant> = None;

    while let Ok(cmd) = rx.recv() {
        match cmd {
            H264ArtCommand::CodecConfig { data } => {
                codec_config = Some(data);
                info!("map album art h264: stored codec config");
            }
            H264ArtCommand::VideoFrame { data, options } => {
                let interval = Duration::from_millis(options.capture_interval_ms);
                if options.capture_interval_ms > 0 {
                    if let Some(last) = last_emit_at {
                        if last.elapsed() < interval {
                            continue;
                        }
                    }
                }

                let Some(codec_config) = codec_config.as_ref() else {
                    throttle_warn(&mut last_warn_at, "map album art h264: IDR arrived before codec config; skipping");
                    continue;
                };

                match decode_idr_to_png(codec_config, &data, &options) {
                    Ok(png) => {
                        if let Err(e) = validate_png(&png, options.max_bytes) {
                            throttle_warn(
                                &mut last_warn_at,
                                &format!("map album art h264: generated PNG rejected: {}", e),
                            );
                            continue;
                        }
                        let bytes = png.len();
                        let version = global_album_art_store().set_png(RUST_H264_SOURCE, png);
                        last_emit_at = Some(Instant::now());
                        info!(
                            "map album art h264: captured map frame as PNG ({} bytes, version={})",
                            bytes,
                            version
                        );
                    }
                    Err(e) => {
                        throttle_warn(
                            &mut last_warn_at,
                            &format!("map album art h264: failed to decode/capture IDR: {}", e),
                        );
                    }
                }
            }
        }
    }
}

fn throttle_warn(last_warn_at: &mut Option<Instant>, message: &str) {
    let should_log = last_warn_at
        .map(|instant| instant.elapsed() >= Duration::from_secs(5))
        .unwrap_or(true);
    if should_log {
        warn!("{}", message);
        *last_warn_at = Some(Instant::now());
    }
}

fn decode_idr_to_png(
    codec_config: &[u8],
    data: &[u8],
    options: &H264ArtOptions,
) -> Result<Vec<u8>, String> {
    let mut bitstream = Vec::with_capacity(codec_config.len() + data.len() + 8);
    bitstream.extend_from_slice(codec_config);
    bitstream.extend_from_slice(data);

    let nals = parse_annex_b(&bitstream);
    if nals.is_empty() {
        return Err("no Annex-B NAL units found".to_string());
    }

    let mut decoder = Decoder::new();
    let mut decoded: Option<Frame> = None;

    for nal in &nals {
        match decoder.decode_nal(nal) {
            Ok(Some(frame)) => decoded = Some(frame),
            Ok(None) => {}
            Err(e) => return Err(format!("decoder error: {}", e)),
        }
    }

    if let Some(frame) = decoder.flush() {
        decoded = Some(frame);
    }

    let Some(frame) = decoded else {
        return Err("decoder produced no frame".to_string());
    };

    frame_to_png(&frame, options)
}

fn frame_to_png(frame: &Frame, options: &H264ArtOptions) -> Result<Vec<u8>, String> {
    let width = frame.width as usize;
    let height = frame.height as usize;
    if width == 0 || height == 0 {
        return Err("decoded frame has empty dimensions".to_string());
    }
    if frame.y.len() < width.saturating_mul(height) {
        return Err("decoded frame Y plane is shorter than expected".to_string());
    }

    let crop = compute_crop(width, height, options);
    let output_size = options.output_size_px as usize;
    let mut rgb = vec![0u8; output_size * output_size * 3];

    for oy in 0..output_size {
        let sy = crop.y + (oy * crop.h / output_size);
        for ox in 0..output_size {
            let sx = crop.x + (ox * crop.w / output_size);
            let (r, g, b) = yuv420_pixel_to_rgb(frame, width, height, sx, sy);
            let idx = (oy * output_size + ox) * 3;
            rgb[idx] = r;
            rgb[idx + 1] = g;
            rgb[idx + 2] = b;
        }
    }

    encode_rgb_png(output_size as u32, output_size as u32, &rgb)
}

#[derive(Clone, Copy, Debug)]
struct CropRect {
    x: usize,
    y: usize,
    w: usize,
    h: usize,
}

fn compute_crop(width: usize, height: usize, options: &H264ArtOptions) -> CropRect {
    let crop_w = percent_size(width, options.crop_w_percent).unwrap_or(width).min(width).max(1);
    let crop_h = percent_size(height, options.crop_h_percent).unwrap_or(height).min(height).max(1);

    let max_x = width.saturating_sub(crop_w);
    let max_y = height.saturating_sub(crop_h);
    let x = (width.saturating_mul(options.crop_x_percent as usize) / 100).min(max_x);
    let y = (height.saturating_mul(options.crop_y_percent as usize) / 100).min(max_y);

    CropRect {
        x,
        y,
        w: crop_w,
        h: crop_h,
    }
}

fn percent_size(total: usize, percent: u8) -> Option<usize> {
    if percent == 0 {
        None
    } else {
        Some((total.saturating_mul(percent as usize) / 100).max(1))
    }
}

fn yuv420_pixel_to_rgb(frame: &Frame, width: usize, height: usize, x: usize, y: usize) -> (u8, u8, u8) {
    let sx = x.min(width.saturating_sub(1));
    let sy = y.min(height.saturating_sub(1));
    let y_value = frame.y[sy * width + sx] as i32;

    let chroma_w = (width / 2).max(1);
    let chroma_h = (height / 2).max(1);
    let chroma_x = (sx / 2).min(chroma_w.saturating_sub(1));
    let chroma_y = (sy / 2).min(chroma_h.saturating_sub(1));
    let chroma_idx = chroma_y * chroma_w + chroma_x;

    let u_value = frame.u.get(chroma_idx).copied().unwrap_or(128) as i32;
    let v_value = frame.v.get(chroma_idx).copied().unwrap_or(128) as i32;

    // BT.601 limited-range YUV -> RGB, good enough for map preview artwork.
    let c = y_value - 16;
    let d = u_value - 128;
    let e = v_value - 128;

    let r = (298 * c + 409 * e + 128) >> 8;
    let g = (298 * c - 100 * d - 208 * e + 128) >> 8;
    let b = (298 * c + 516 * d + 128) >> 8;

    (clamp_u8(r), clamp_u8(g), clamp_u8(b))
}

fn clamp_u8(value: i32) -> u8 {
    value.clamp(0, 255) as u8
}

fn encode_rgb_png(width: u32, height: u32, rgb: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|e| format!("png write_header failed: {}", e))?;
        writer
            .write_image_data(rgb)
            .map_err(|e| format!("png write_image_data failed: {}", e))?;
    }
    Ok(out)
}

fn clamp_output_size(value: u32) -> u32 {
    let value = if value == 0 { DEFAULT_OUTPUT_SIZE } else { value };
    value.clamp(MIN_OUTPUT_SIZE, MAX_OUTPUT_SIZE)
}

fn contains_idr_nal(data: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 4 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            let start_code_len = if data.get(i + 2) == Some(&1) {
                3
            } else if data.get(i + 2) == Some(&0) && data.get(i + 3) == Some(&1) {
                4
            } else {
                i += 1;
                continue;
            };

            let nal_start = i + start_code_len;
            if let Some(&header) = data.get(nal_start) {
                if header & 0x1F == 5 {
                    return true;
                }
            }
            i = nal_start.saturating_add(1);
        } else {
            i += 1;
        }
    }
    false
}
