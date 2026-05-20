use crate::config::AppConfig;
use crate::mitm::{Packet, FRAME_TYPE_FIRST, FRAME_TYPE_LAST, FRAME_TYPE_MASK};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs;

/// MediaPlaybackStatusMessageId::MEDIA_PLAYBACK_METADATA.
/// Kept as a constant here so this helper only needs raw packet/protobuf bytes.
const MEDIA_PLAYBACK_METADATA_ID: i32 = 0x8003;

#[derive(Default)]
pub(crate) struct MapAlbumArtInjector {
    states: HashMap<u8, AlbumArtPatchState>,
}

struct AlbumArtPatchState {
    next_payload_pos: usize,
    album_art_start: usize,
    album_art_len: usize,
    replacement: Vec<u8>,
    patched_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocateError {
    Incomplete,
    Malformed,
    NotFound,
}

impl MapAlbumArtInjector {
    pub(crate) fn patch_packet(&mut self, pkt: &mut Packet, message_id: i32, cfg: &AppConfig) {
        if !cfg.map_album_art_enabled {
            self.states.clear();
            return;
        }

        let frame_kind = pkt.flags & FRAME_TYPE_MASK;
        let is_first = (frame_kind & FRAME_TYPE_FIRST) == FRAME_TYPE_FIRST;
        let is_last = (frame_kind & FRAME_TYPE_LAST) == FRAME_TYPE_LAST;

        if is_first {
            // A new fragmented/standalone message starts on this channel. If an old
            // metadata message was still pending, abandon it rather than applying
            // offsets to an unrelated stream.
            if self.states.remove(&pkt.channel).is_some() {
                warn!(
                    "map album art: replacing incomplete metadata patch state on channel {:#04x}",
                    pkt.channel
                );
            }

            if message_id != MEDIA_PLAYBACK_METADATA_ID || pkt.payload.len() < 2 {
                return;
            }

            let Some(mut replacement) = load_png_replacement(cfg) else {
                return;
            };

            let proto = &pkt.payload[2..];
            let (art_start_in_proto, art_len) = match locate_album_art_field(proto) {
                Ok(found) => found,
                Err(LocateError::NotFound) => {
                    debug!(
                        "map album art: MEDIA_PLAYBACK_METADATA on channel {:#04x} has no album_art field",
                        pkt.channel
                    );
                    return;
                }
                Err(LocateError::Incomplete) => {
                    warn!(
                        "map album art: album_art field was not fully discoverable in first metadata fragment on channel {:#04x}; leaving metadata unchanged",
                        pkt.channel
                    );
                    return;
                }
                Err(LocateError::Malformed) => {
                    warn!(
                        "map album art: malformed MEDIA_PLAYBACK_METADATA protobuf on channel {:#04x}; leaving metadata unchanged",
                        pkt.channel
                    );
                    return;
                }
            };

            if replacement.len() > art_len {
                warn!(
                    "map album art: replacement PNG is too large for in-place patch on channel {:#04x}: replacement={} original_album_art={}. Leaving metadata unchanged. Reduce image size or quality.",
                    pkt.channel,
                    replacement.len(),
                    art_len
                );
                return;
            }

            // Keep the protobuf and AA transport frame lengths unchanged. PNG readers
            // normally ignore trailing bytes after IEND, so zero-padding a smaller PNG
            // inside the original bytes field is a low-risk first implementation.
            replacement.resize(art_len, 0);

            let mut state = AlbumArtPatchState {
                next_payload_pos: 0,
                // +2 because pkt.payload starts with the AA message id before protobuf bytes.
                album_art_start: 2 + art_start_in_proto,
                album_art_len: art_len,
                replacement,
                patched_bytes: 0,
            };

            patch_fragment_bytes(pkt, &mut state);

            if is_last {
                log_patch_summary(pkt.channel, &state);
            } else {
                self.states.insert(pkt.channel, state);
            }
            return;
        }

        if let Some(state) = self.states.get_mut(&pkt.channel) {
            patch_fragment_bytes(pkt, state);
            if is_last {
                if let Some(state) = self.states.remove(&pkt.channel) {
                    log_patch_summary(pkt.channel, &state);
                }
            }
        }
    }
}

fn log_patch_summary(channel: u8, state: &AlbumArtPatchState) {
    if state.patched_bytes == state.album_art_len {
        info!(
            "map album art: patched MEDIA_PLAYBACK_METADATA album_art on channel {:#04x} ({} bytes)",
            channel, state.album_art_len
        );
    } else {
        warn!(
            "map album art: patched partial album_art on channel {:#04x}: patched={} expected={}",
            channel, state.patched_bytes, state.album_art_len
        );
    }
}

fn patch_fragment_bytes(pkt: &mut Packet, state: &mut AlbumArtPatchState) {
    let frag_start = state.next_payload_pos;
    let frag_end = frag_start.saturating_add(pkt.payload.len());
    let art_start = state.album_art_start;
    let art_end = state.album_art_start.saturating_add(state.album_art_len);

    let copy_start = frag_start.max(art_start);
    let copy_end = frag_end.min(art_end);

    if copy_start < copy_end {
        let dst_start = copy_start - frag_start;
        let src_start = copy_start - art_start;
        let len = copy_end - copy_start;
        pkt.payload[dst_start..dst_start + len]
            .copy_from_slice(&state.replacement[src_start..src_start + len]);
        state.patched_bytes = state.patched_bytes.saturating_add(len);
    }

    state.next_payload_pos = frag_end;
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

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, LocateError> {
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
            return Err(LocateError::Malformed);
        }
    }

    Err(LocateError::Incomplete)
}

fn skip_bytes(data: &[u8], pos: &mut usize, len: usize) -> Result<(), LocateError> {
    if data.len().saturating_sub(*pos) < len {
        return Err(LocateError::Incomplete);
    }
    *pos += len;
    Ok(())
}

/// Returns `(album_art_data_start, album_art_len)` relative to the protobuf payload.
fn locate_album_art_field(data: &[u8]) -> Result<(usize, usize), LocateError> {
    let mut pos = 0usize;

    while pos < data.len() {
        let key = read_varint(data, &mut pos)?;
        if key == 0 {
            return Err(LocateError::Malformed);
        }

        let field_no = key >> 3;
        let wire_type = key & 0x07;

        match wire_type {
            // varint
            0 => {
                let _ = read_varint(data, &mut pos)?;
            }
            // fixed64
            1 => skip_bytes(data, &mut pos, 8)?,
            // length-delimited
            2 => {
                let len = read_varint(data, &mut pos)? as usize;
                let value_start = pos;

                // The album_art bytes field is normally much larger than one AA
                // transport fragment. For field 4 we only need the value start
                // and total protobuf length; the actual bytes can continue in
                // following fragments and will be patched by absolute offset.
                if field_no == 4 {
                    return Ok((value_start, len));
                }

                if data.len().saturating_sub(pos) < len {
                    return Err(LocateError::Incomplete);
                }
                pos += len;
            }
            // fixed32
            5 => skip_bytes(data, &mut pos, 4)?,
            _ => return Err(LocateError::Malformed),
        }
    }

    Err(LocateError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::{ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST};

    fn packet(channel: u8, flags: u8, payload: Vec<u8>) -> Packet {
        Packet {
            channel,
            flags: ENCRYPTED | flags,
            final_length: None,
            payload,
        }
    }

    #[test]
    fn locate_album_art_field_finds_field_4() {
        // song="A", artist="B", album="C", album_art=[1,2,3], duration=10
        let proto = [
            0x0A, 0x01, b'A', 0x12, 0x01, b'B', 0x1A, 0x01, b'C', 0x22, 0x03, 0x01, 0x02,
            0x03, 0x30, 0x0A,
        ];
        assert_eq!(locate_album_art_field(&proto), Ok((11, 3)));
    }

    #[test]
    fn locate_album_art_field_accepts_fragmented_field_4_value() {
        // field 1 = title "A", field 4 = length 6 but only the first 2 bytes
        // of the value are present in this AA fragment.
        let proto = [0x0A, 0x01, b'A', 0x22, 0x06, 0x89, 0x50];
        assert_eq!(locate_album_art_field(&proto), Ok((5, 6)));
    }

    #[test]
    fn patch_fragment_bytes_patches_across_chunks() {
        let mut state = AlbumArtPatchState {
            next_payload_pos: 0,
            album_art_start: 5,
            album_art_len: 6,
            replacement: b"ABCDEF".to_vec(),
            patched_bytes: 0,
        };

        let mut first = packet(0x08, FRAME_TYPE_FIRST, b"00123".to_vec());
        patch_fragment_bytes(&mut first, &mut state);
        assert_eq!(&first.payload, b"00123");

        let mut middle = packet(0x08, 0, b"456789".to_vec());
        patch_fragment_bytes(&mut middle, &mut state);
        assert_eq!(&middle.payload, b"ABCDEF");

        let mut last = packet(0x08, FRAME_TYPE_LAST, b"xx".to_vec());
        patch_fragment_bytes(&mut last, &mut state);
        assert_eq!(&last.payload, b"xx");
        assert_eq!(state.patched_bytes, 6);
    }
}
