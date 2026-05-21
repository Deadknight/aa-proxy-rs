use crate::config::AppConfig;
use crate::mitm::{Packet, FRAME_TYPE_FIRST, FRAME_TYPE_LAST, FRAME_TYPE_MASK};
use crate::packet_fragment::{
    clamp_first_fragment_payload_bytes, fragment_plain_payload, frame_base_flags,
    openauto_continuation_fragment_payload_bytes, PlainPayloadFragmentOptions,
    DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES, MAX_FIRST_FRAGMENT_PAYLOAD_BYTES,
    MIN_FIRST_FRAGMENT_PAYLOAD_BYTES,
};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs;

/// MediaPlaybackStatusMessageId::MEDIA_PLAYBACK_METADATA.
/// Kept as a constant here so this helper only needs raw packet/protobuf bytes.
const MEDIA_PLAYBACK_METADATA_ID: i32 = 0x8003;

#[derive(Default)]
pub(crate) struct MapAlbumArtInjector {
    states: HashMap<u8, AlbumArtRewriteState>,
}

pub(crate) enum AlbumArtProcessResult {
    /// Leave the current packet untouched and let the normal forwarding path handle it.
    Forward,
    /// Drop the current original fragment. A rewritten message will be emitted when the last
    /// fragment arrives.
    Drop,
    /// Replace the original message with these complete, re-fragmented packets.
    Replace(Vec<Packet>),
}

struct AlbumArtRewriteState {
    payload: Vec<u8>,
    replacement: Vec<u8>,
    base_flags: u8,
    first_final_length: Option<u32>,
    original_fragments: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RewriteError {
    Malformed,
    NotFound,
}

impl MapAlbumArtInjector {
    pub(crate) fn clear(&mut self) {
        self.states.clear();
    }

    pub(crate) fn process_packet(
        &mut self,
        pkt: &Packet,
        message_id: i32,
        cfg: &AppConfig,
    ) -> AlbumArtProcessResult {
        if !cfg.map_album_art_enabled {
            self.states.clear();
            return AlbumArtProcessResult::Forward;
        }

        let frame_kind = pkt.flags & FRAME_TYPE_MASK;
        let is_first = frame_kind == FRAME_TYPE_FIRST || frame_kind == (FRAME_TYPE_FIRST | FRAME_TYPE_LAST);
        let is_last = frame_kind == FRAME_TYPE_LAST || frame_kind == (FRAME_TYPE_FIRST | FRAME_TYPE_LAST);

        if is_first {
            // A new fragmented/standalone message starts on this channel. If an old
            // metadata message was still pending, abandon it rather than applying
            // offsets to an unrelated stream.
            if self.states.remove(&pkt.channel).is_some() {
                warn!(
                    "map album art: replacing incomplete metadata rewrite state on channel {:#04x}",
                    pkt.channel
                );
            }

            if message_id != MEDIA_PLAYBACK_METADATA_ID || pkt.payload.len() < 2 {
                return AlbumArtProcessResult::Forward;
            }

            let Some(replacement) = load_png_replacement(cfg) else {
                return AlbumArtProcessResult::Forward;
            };

            let base_flags = frame_base_flags(pkt.flags);

            if is_last {
                return self.finish_rewrite(
                    pkt.channel,
                    base_flags,
                    pkt.payload.clone(),
                    replacement,
                    pkt.final_length,
                    1,
                    cfg,
                );
            }

            self.states.insert(
                pkt.channel,
                AlbumArtRewriteState {
                    payload: pkt.payload.clone(),
                    replacement,
                    base_flags,
                    first_final_length: pkt.final_length,
                    original_fragments: 1,
                },
            );
            return AlbumArtProcessResult::Drop;
        }

        if let Some(state) = self.states.get_mut(&pkt.channel) {
            state.payload.extend_from_slice(&pkt.payload);
            state.original_fragments = state.original_fragments.saturating_add(1);

            if is_last {
                if let Some(state) = self.states.remove(&pkt.channel) {
                    return self.finish_rewrite(
                        pkt.channel,
                        state.base_flags,
                        state.payload,
                        state.replacement,
                        state.first_final_length,
                        state.original_fragments,
                        cfg,
                    );
                }
            }

            return AlbumArtProcessResult::Drop;
        }

        AlbumArtProcessResult::Forward
    }

    fn finish_rewrite(
        &self,
        channel: u8,
        base_flags: u8,
        original_payload: Vec<u8>,
        replacement: Vec<u8>,
        first_final_length: Option<u32>,
        original_fragments: usize,
        cfg: &AppConfig,
    ) -> AlbumArtProcessResult {
        let chunk_bytes = effective_chunk_bytes(cfg);

        let original_payload_len = original_payload.len();
        let (rewritten_payload, replaced_album_art) = match rewrite_album_art_payload(&original_payload, &replacement) {
            Ok(payload) => (payload, true),
            Err(RewriteError::NotFound) => {
                debug!(
                    "map album art: MEDIA_PLAYBACK_METADATA on channel {:#04x} has no album_art field; replaying original metadata",
                    channel
                );
                (original_payload, false)
            }
            Err(RewriteError::Malformed) => {
                warn!(
                    "map album art: malformed MEDIA_PLAYBACK_METADATA protobuf on channel {:#04x}; replaying original metadata",
                    channel
                );
                (original_payload, false)
            }
        };

        // OpenAuto/aasdk and the captured AA traces both show that the FIRST
        // frame extended length is the total plaintext/application payload
        // length, not the encrypted byte count. The normal transmit path will
        // fill each frame's 2-byte payload size after TLS encryption.
        let rewritten_final_length = Some(rewritten_payload.len() as u32);
        let continuation_chunk_bytes = openauto_continuation_fragment_payload_bytes(chunk_bytes);
        let rewritten = fragment_plain_payload(
            &rewritten_payload,
            PlainPayloadFragmentOptions {
                channel,
                base_flags,
                first_fragment_payload_bytes: chunk_bytes,
                continuation_fragment_payload_bytes: continuation_chunk_bytes,
                first_final_length: rewritten_final_length,
            },
        );

        if replaced_album_art {
            info!(
                "map album art: rewrote MEDIA_PLAYBACK_METADATA album_art on channel {:#04x} (mode=dynamic original_payload={} rewritten_payload={} replacement_png={} original_fragments={} rewritten_fragments={} chunk_bytes={} original_final_length={:?} rewritten_final_length={:?})",
                channel,
                original_payload_len,
                rewritten_payload.len(),
                replacement.len(),
                original_fragments,
                rewritten.len(),
                chunk_bytes,
                first_final_length,
                rewritten_final_length
            );
        } else {
            info!(
                "map album art: replayed MEDIA_PLAYBACK_METADATA unchanged on channel {:#04x} (mode=dynamic payload={} fragments={} chunk_bytes={} original_final_length={:?} rewritten_final_length={:?})",
                channel,
                rewritten_payload.len(),
                rewritten.len(),
                chunk_bytes,
                first_final_length,
                rewritten_final_length
            );
        }

        AlbumArtProcessResult::Replace(rewritten)
    }
}

fn load_png_replacement(cfg: &AppConfig) -> Option<Vec<u8>> {
    let path = &cfg.map_album_art_file;
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            warn!(
                "map album art: cannot read replacement PNG {}: {}",
                path.display(),
                e
            );
            return None;
        }
    };

    if data.is_empty() {
        warn!("map album art: replacement file {} is empty", path.display());
        return None;
    }

    if data.len() > cfg.map_album_art_max_bytes {
        warn!(
            "map album art: replacement file {} is larger than map_album_art_max_bytes ({} > {})",
            path.display(),
            data.len(),
            cfg.map_album_art_max_bytes
        );
        return None;
    }

    if !is_png(&data) {
        warn!(
            "map album art: replacement file {} is not a PNG; expected PNG signature",
            path.display()
        );
        return None;
    }

    Some(data)
}

fn is_png(data: &[u8]) -> bool {
    data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
}

fn effective_chunk_bytes(cfg: &AppConfig) -> usize {
    let requested = if cfg.map_album_art_chunk_bytes == 0 {
        DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES
    } else {
        cfg.map_album_art_chunk_bytes
    };

    let clamped = clamp_first_fragment_payload_bytes(requested);
    if clamped != requested {
        warn!(
            "map album art: map_album_art_chunk_bytes={} is outside supported range {}..={}; using {}",
            requested, MIN_FIRST_FRAGMENT_PAYLOAD_BYTES, MAX_FIRST_FRAGMENT_PAYLOAD_BYTES, clamped
        );
    }
    clamped
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, RewriteError> {
    let mut value = 0u64;
    let mut shift = 0u32;

    while *pos < data.len() {
        let byte = data[*pos];
        *pos += 1;
        value |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            return Ok(value);
        }

        shift += 7;
        if shift >= 64 {
            return Err(RewriteError::Malformed);
        }
    }

    Err(RewriteError::Malformed)
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(((value as u8) & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn skip_checked(data: &[u8], pos: &mut usize, len: usize) -> Result<(), RewriteError> {
    if data.len().saturating_sub(*pos) < len {
        return Err(RewriteError::Malformed);
    }
    *pos += len;
    Ok(())
}

fn rewrite_album_art_payload(payload: &[u8], replacement: &[u8]) -> Result<Vec<u8>, RewriteError> {
    if payload.len() < 2 {
        return Err(RewriteError::Malformed);
    }

    let mut out = Vec::with_capacity(payload.len().saturating_sub(0).max(replacement.len() + 16));
    out.extend_from_slice(&payload[..2]);

    let data = &payload[2..];
    let mut pos = 0usize;
    let mut replaced = false;

    while pos < data.len() {
        let field_start = pos;
        let key = read_varint(data, &mut pos)?;
        if key == 0 {
            return Err(RewriteError::Malformed);
        }

        let field_no = key >> 3;
        let wire_type = key & 0x07;

        match wire_type {
            // varint
            0 => {
                let _ = read_varint(data, &mut pos)?;
                out.extend_from_slice(&data[field_start..pos]);
            }
            // fixed64
            1 => {
                skip_checked(data, &mut pos, 8)?;
                out.extend_from_slice(&data[field_start..pos]);
            }
            // length-delimited
            2 => {
                let len = read_varint(data, &mut pos)? as usize;
                let value_start = pos;
                skip_checked(data, &mut pos, len)?;

                if field_no == 4 && !replaced {
                    write_varint(key, &mut out);
                    write_varint(replacement.len() as u64, &mut out);
                    out.extend_from_slice(replacement);
                    replaced = true;
                } else {
                    out.extend_from_slice(&data[field_start..pos]);
                }

                // Keep the original value_start calculation above explicit. It makes
                // malformed length-delimited fields fail before any output is emitted
                // for that field.
                let _ = value_start;
            }
            // fixed32
            5 => {
                skip_checked(data, &mut pos, 4)?;
                out.extend_from_slice(&data[field_start..pos]);
            }
            _ => return Err(RewriteError::Malformed),
        }
    }

    if replaced {
        Ok(out)
    } else {
        Err(RewriteError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, DEFAULT_MAP_ALBUM_ART_FILE};
    use crate::mitm::{ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST};

    fn packet(channel: u8, flags: u8, payload: Vec<u8>) -> Packet {
        Packet {
            channel,
            flags: ENCRYPTED | flags,
            final_length: None,
            payload,
        }
    }

    fn test_config() -> AppConfig {
        AppConfig {
            map_album_art_file: DEFAULT_MAP_ALBUM_ART_FILE.into(),
            map_album_art_max_bytes: 262_144,
            map_album_art_chunk_bytes: 16,
            ..AppConfig::default()
        }
    }

    fn metadata_payload(album_art: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x80, 0x03];
        payload.extend_from_slice(&[0x0A, 0x01, b'A']);
        payload.extend_from_slice(&[0x12, 0x01, b'B']);
        payload.extend_from_slice(&[0x1A, 0x01, b'C']);
        payload.push(0x22);
        write_varint(album_art.len() as u64, &mut payload);
        payload.extend_from_slice(album_art);
        payload.extend_from_slice(&[0x30, 0x0A]);
        payload
    }

    fn extract_album_art(payload: &[u8]) -> Vec<u8> {
        let data = &payload[2..];
        let mut pos = 0usize;

        while pos < data.len() {
            let key = read_varint(data, &mut pos).unwrap();
            let field_no = key >> 3;
            let wire_type = key & 0x07;
            match wire_type {
                0 => {
                    let _ = read_varint(data, &mut pos).unwrap();
                }
                1 => pos += 8,
                2 => {
                    let len = read_varint(data, &mut pos).unwrap() as usize;
                    let value_start = pos;
                    pos += len;
                    if field_no == 4 {
                        return data[value_start..value_start + len].to_vec();
                    }
                }
                5 => pos += 4,
                _ => panic!("unexpected wire type"),
            }
        }
        panic!("album art not found")
    }

    #[test]
    fn rewrite_album_art_payload_uses_dynamic_replacement_length() {
        let original_art = vec![0x11; 3];
        let replacement = vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4, 5, 6];
        let payload = metadata_payload(&original_art);

        let rewritten = rewrite_album_art_payload(&payload, &replacement).unwrap();

        assert_eq!(extract_album_art(&rewritten), replacement);
        assert!(rewritten.len() > payload.len());
    }

    #[test]
    fn openauto_fragment_utility_sets_first_final_length_only_for_multi_fragment_messages() {
        let payload = metadata_payload(&vec![0x55; 40]);
        let packets = fragment_plain_payload(
            &payload,
            PlainPayloadFragmentOptions {
                channel: 0x08,
                base_flags: ENCRYPTED,
                first_fragment_payload_bytes: 16,
                continuation_fragment_payload_bytes: 20,
                first_final_length: Some(payload.len() as u32),
            },
        );

        assert!(packets.len() > 1);
        assert_eq!(packets[0].flags & FRAME_TYPE_MASK, FRAME_TYPE_FIRST);
        assert_eq!(packets[0].final_length, Some(payload.len() as u32));
        assert_eq!(packets.last().unwrap().flags & FRAME_TYPE_MASK, FRAME_TYPE_LAST);
        assert_eq!(packets.last().unwrap().final_length, None);
    }

    #[test]
    fn process_packet_drops_original_fragments_and_emits_rewritten_metadata() {
        let replacement = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4];
        let original = metadata_payload(&vec![0x22; 8]);
        let first_payload = original[..10].to_vec();
        let last_payload = original[10..].to_vec();

        let mut injector = MapAlbumArtInjector::default();
        let mut cfg = test_config();
        let tmp_path = std::env::temp_dir().join(format!(
            "aa-proxy-map-album-art-test-{}.png",
            std::process::id()
        ));
        std::fs::write(&tmp_path, &replacement).unwrap();
        cfg.map_album_art_file = tmp_path.clone();

        let first = packet(0x08, FRAME_TYPE_FIRST, first_payload);
        match injector.process_packet(&first, MEDIA_PLAYBACK_METADATA_ID, &cfg) {
            AlbumArtProcessResult::Drop => {}
            _ => panic!("first original fragment should be dropped"),
        }

        let last = packet(0x08, FRAME_TYPE_LAST, last_payload);
        let rewritten_packets = match injector.process_packet(&last, MEDIA_PLAYBACK_METADATA_ID, &cfg) {
            AlbumArtProcessResult::Replace(packets) => packets,
            _ => panic!("last fragment should emit rewritten metadata"),
        };

        let mut reassembled = Vec::new();
        for pkt in rewritten_packets {
            reassembled.extend_from_slice(&pkt.payload);
        }

        assert_eq!(extract_album_art(&reassembled), replacement);
        let _ = std::fs::remove_file(tmp_path);
    }
}
