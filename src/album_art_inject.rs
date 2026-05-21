use crate::config::AppConfig;
use crate::mitm::{Packet, FRAME_TYPE_FIRST, FRAME_TYPE_LAST, FRAME_TYPE_MASK};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs;

/// MediaPlaybackStatusMessageId::MEDIA_PLAYBACK_METADATA.
/// Kept as a constant here so this helper only needs raw packet/protobuf bytes.
const MEDIA_PLAYBACK_METADATA_ID: i32 = 0x8003;
const DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES: usize = 16_120;
const CONTINUATION_FRAGMENT_PAYLOAD_BONUS: usize = 4;

#[derive(Default)]
pub(crate) struct MapAlbumArtInjector {
    in_place_states: HashMap<u8, AlbumArtPatchState>,
    dynamic_states: HashMap<u8, AlbumArtDynamicState>,
}

struct AlbumArtPatchState {
    next_payload_pos: usize,
    album_art_start: usize,
    album_art_len: usize,
    replacement: Vec<u8>,
    patched_bytes: usize,
}

struct AlbumArtDynamicState {
    channel: u8,
    base_flags: u8,
    first_final_length: Option<u32>,
    original_packets: Vec<Packet>,
    original_payload: Vec<u8>,
    original_fragment_lengths: Vec<usize>,
}

pub(crate) enum AlbumArtProcessResult {
    Forward,
    Drop,
    Replace(Vec<Packet>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocateError {
    Incomplete,
    Malformed,
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AlbumArtFieldLocation {
    len_start: usize,
    value_start: usize,
    value_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RewriteMode {
    InPlace,
    Identity,
    Dynamic,
}

impl RewriteMode {
    fn from_config(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "identity" => Self::Identity,
            "dynamic" => Self::Dynamic,
            "in_place" | "in-place" | "inplace" | "pad" | "padded" => Self::InPlace,
            other => {
                warn!(
                    "map album art: unknown map_album_art_rewrite_mode '{}'; falling back to in_place",
                    other
                );
                Self::InPlace
            }
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::InPlace => "in_place",
            Self::Identity => "identity",
            Self::Dynamic => "dynamic",
        }
    }
}

impl MapAlbumArtInjector {
    pub(crate) fn clear(&mut self) {
        self.in_place_states.clear();
        self.dynamic_states.clear();
    }

    pub(crate) fn process_packet(
        &mut self,
        pkt: &mut Packet,
        message_id: i32,
        cfg: &AppConfig,
    ) -> AlbumArtProcessResult {
        if !cfg.map_album_art_enabled {
            self.clear();
            return AlbumArtProcessResult::Forward;
        }

        match RewriteMode::from_config(&cfg.map_album_art_rewrite_mode) {
            RewriteMode::InPlace => {
                self.patch_packet_in_place(pkt, message_id, cfg);
                AlbumArtProcessResult::Forward
            }
            mode @ (RewriteMode::Identity | RewriteMode::Dynamic) => {
                self.process_packet_dynamic(pkt, message_id, cfg, mode)
            }
        }
    }

    fn patch_packet_in_place(&mut self, pkt: &mut Packet, message_id: i32, cfg: &AppConfig) {
        let frame_kind = pkt.flags & FRAME_TYPE_MASK;
        let is_first = (frame_kind & FRAME_TYPE_FIRST) == FRAME_TYPE_FIRST;
        let is_last = (frame_kind & FRAME_TYPE_LAST) == FRAME_TYPE_LAST;

        if is_first {
            // A new fragmented/standalone message starts on this channel. If an old
            // metadata message was still pending, abandon it rather than applying
            // offsets to an unrelated stream.
            if self.in_place_states.remove(&pkt.channel).is_some() {
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
            let location = match locate_album_art_field_location(proto) {
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

            if replacement.len() > location.value_len {
                warn!(
                    "map album art: replacement PNG is too large for in-place patch on channel {:#04x}: replacement={} original_album_art={}. Leaving metadata unchanged. Use dynamic mode or reduce image size/quality.",
                    pkt.channel,
                    replacement.len(),
                    location.value_len
                );
                return;
            }

            // Keep the protobuf and AA transport frame lengths unchanged. PNG readers
            // normally ignore trailing bytes after IEND, so zero-padding a smaller PNG
            // inside the original bytes field preserves the transport layout.
            replacement.resize(location.value_len, 0);

            let mut state = AlbumArtPatchState {
                next_payload_pos: 0,
                // +2 because pkt.payload starts with the AA message id before protobuf bytes.
                album_art_start: 2 + location.value_start,
                album_art_len: location.value_len,
                replacement,
                patched_bytes: 0,
            };

            patch_fragment_bytes(pkt, &mut state);

            if is_last {
                log_in_place_summary(pkt.channel, &state);
            } else {
                self.in_place_states.insert(pkt.channel, state);
            }
            return;
        }

        if let Some(state) = self.in_place_states.get_mut(&pkt.channel) {
            patch_fragment_bytes(pkt, state);
            if is_last {
                if let Some(state) = self.in_place_states.remove(&pkt.channel) {
                    log_in_place_summary(pkt.channel, &state);
                }
            }
        }
    }

    fn process_packet_dynamic(
        &mut self,
        pkt: &Packet,
        message_id: i32,
        cfg: &AppConfig,
        mode: RewriteMode,
    ) -> AlbumArtProcessResult {
        let frame_kind = pkt.flags & FRAME_TYPE_MASK;
        let is_first = (frame_kind & FRAME_TYPE_FIRST) == FRAME_TYPE_FIRST;
        let is_last = (frame_kind & FRAME_TYPE_LAST) == FRAME_TYPE_LAST;

        if is_first {
            if self.dynamic_states.remove(&pkt.channel).is_some() {
                warn!(
                    "map album art: replacing incomplete dynamic metadata state on channel {:#04x}",
                    pkt.channel
                );
            }

            if message_id != MEDIA_PLAYBACK_METADATA_ID || pkt.payload.len() < 2 {
                return AlbumArtProcessResult::Forward;
            }

            let mut state = AlbumArtDynamicState {
                channel: pkt.channel,
                base_flags: pkt.flags & !FRAME_TYPE_MASK,
                first_final_length: pkt.final_length,
                original_packets: vec![pkt.clone()],
                original_payload: pkt.payload.clone(),
                original_fragment_lengths: vec![pkt.payload.len()],
            };

            if is_last {
                return self.finish_dynamic_state(state, cfg, mode);
            }

            self.dynamic_states.insert(pkt.channel, state);
            return AlbumArtProcessResult::Drop;
        }

        let Some(state) = self.dynamic_states.get_mut(&pkt.channel) else {
            return AlbumArtProcessResult::Forward;
        };

        state.original_packets.push(pkt.clone());
        state.original_fragment_lengths.push(pkt.payload.len());
        state.original_payload.extend_from_slice(&pkt.payload);

        if is_last {
            if let Some(state) = self.dynamic_states.remove(&pkt.channel) {
                return self.finish_dynamic_state(state, cfg, mode);
            }
        }

        AlbumArtProcessResult::Drop
    }

    fn finish_dynamic_state(
        &mut self,
        state: AlbumArtDynamicState,
        cfg: &AppConfig,
        mode: RewriteMode,
    ) -> AlbumArtProcessResult {
        let original_payload_len = state.original_payload.len();
        let rewritten_payload = match mode {
            RewriteMode::Identity => state.original_payload.clone(),
            RewriteMode::Dynamic => {
                let Some(replacement) = load_png_replacement(cfg) else {
                    warn!(
                        "map album art: dynamic rewrite failed to load replacement; forwarding original metadata on channel {:#04x}",
                        state.channel
                    );
                    return AlbumArtProcessResult::Replace(state.original_packets);
                };

                match rewrite_album_art_payload(&state.original_payload, &replacement) {
                    Ok(payload) => payload,
                    Err(err) => {
                        warn!(
                            "map album art: dynamic rewrite failed on channel {:#04x}: {}; forwarding original metadata",
                            state.channel, err
                        );
                        return AlbumArtProcessResult::Replace(state.original_packets);
                    }
                }
            }
            RewriteMode::InPlace => unreachable!(),
        };

        let chunk_bytes = normalized_chunk_bytes(cfg.map_album_art_chunk_bytes);
        let packets = fragment_payload_openauto_style(
            state.channel,
            state.base_flags,
            &rewritten_payload,
            chunk_bytes,
        );

        let rewritten_final_length = packets.first().and_then(|pkt| pkt.final_length);
        info!(
            "map album art: rewrote MEDIA_PLAYBACK_METADATA album_art on channel {:#04x} (mode={} original_payload={} rewritten_payload={} original_fragments={} rewritten_fragments={} chunk_bytes={} original_final_length={:?} rewritten_final_length={:?})",
            state.channel,
            mode.as_str(),
            original_payload_len,
            rewritten_payload.len(),
            state.original_fragment_lengths.len(),
            packets.len(),
            chunk_bytes,
            state.first_final_length,
            rewritten_final_length
        );

        AlbumArtProcessResult::Replace(packets)
    }
}

fn log_in_place_summary(channel: u8, state: &AlbumArtPatchState) {
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

fn normalized_chunk_bytes(value: usize) -> usize {
    if value == 0 {
        DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES
    } else {
        value.clamp(1024, 60_000)
    }
}

fn fragment_payload_openauto_style(
    channel: u8,
    base_flags: u8,
    payload: &[u8],
    first_chunk_bytes: usize,
) -> Vec<Packet> {
    if payload.len() <= first_chunk_bytes {
        return vec![Packet {
            channel,
            flags: base_flags | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            final_length: None,
            payload: payload.to_vec(),
        }];
    }

    let mut packets = Vec::new();
    let mut pos = first_chunk_bytes.min(payload.len());

    packets.push(Packet {
        channel,
        flags: base_flags | FRAME_TYPE_FIRST,
        final_length: Some(payload.len() as u32),
        payload: payload[..pos].to_vec(),
    });

    let continuation_chunk_bytes = first_chunk_bytes.saturating_add(CONTINUATION_FRAGMENT_PAYLOAD_BONUS);
    while pos < payload.len() {
        let remaining = payload.len() - pos;
        let take = remaining.min(continuation_chunk_bytes);
        let end = pos + take;
        let is_last = end == payload.len();

        packets.push(Packet {
            channel,
            flags: base_flags | if is_last { FRAME_TYPE_LAST } else { 0 },
            final_length: None,
            payload: payload[pos..end].to_vec(),
        });

        pos = end;
    }

    packets
}

fn rewrite_album_art_payload(original_payload: &[u8], replacement: &[u8]) -> Result<Vec<u8>, String> {
    if original_payload.len() < 2 {
        return Err("payload is too short for AA message id".to_string());
    }

    let proto = &original_payload[2..];
    let location = locate_album_art_field_location(proto).map_err(|err| format!("{:?}", err))?;
    let value_end = location
        .value_start
        .checked_add(location.value_len)
        .ok_or_else(|| "album_art range overflow".to_string())?;

    if value_end > proto.len() {
        return Err("album_art value range exceeds protobuf payload".to_string());
    }

    let mut out = Vec::with_capacity(
        original_payload
            .len()
            .saturating_sub(location.value_len)
            .saturating_add(replacement.len())
            .saturating_add(8),
    );

    let len_start = 2 + location.len_start;
    let value_start = 2 + location.value_start;
    let value_end_abs = 2 + value_end;

    out.extend_from_slice(&original_payload[..len_start]);
    write_varint(replacement.len() as u64, &mut out);
    out.extend_from_slice(replacement);
    out.extend_from_slice(&original_payload[value_end_abs..]);

    Ok(out)
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

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(((value as u8) & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
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
    locate_album_art_field_location(data).map(|location| (location.value_start, location.value_len))
}

fn locate_album_art_field_location(data: &[u8]) -> Result<AlbumArtFieldLocation, LocateError> {
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
                let len_start = pos;
                let len = read_varint(data, &mut pos)? as usize;
                let value_start = pos;

                // The album_art bytes field is normally much larger than one AA
                // transport fragment. For field 4 we only need the value start
                // and total protobuf length; the actual bytes can continue in
                // following fragments and will be patched by absolute offset.
                if field_no == 4 {
                    return Ok(AlbumArtFieldLocation {
                        len_start,
                        value_start,
                        value_len: len,
                    });
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

    #[test]
    fn fragment_payload_uses_openauto_style_continuation_size() {
        let payload = vec![0xAA; 16_120 + 16_124 + 10];
        let packets = fragment_payload_openauto_style(0x08, ENCRYPTED, &payload, 16_120);
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].flags, ENCRYPTED | FRAME_TYPE_FIRST);
        assert_eq!(packets[0].final_length, Some(payload.len() as u32));
        assert_eq!(packets[0].payload.len(), 16_120);
        assert_eq!(packets[1].flags, ENCRYPTED);
        assert_eq!(packets[1].payload.len(), 16_124);
        assert_eq!(packets[2].flags, ENCRYPTED | FRAME_TYPE_LAST);
        assert_eq!(packets[2].payload.len(), 10);
    }

    #[test]
    fn dynamic_rewrite_changes_album_art_length() {
        let original = [0x80, 0x03, 0x0A, 0x01, b'A', 0x22, 0x03, 1, 2, 3, 0x30, 0x0A];
        let replacement = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 9, 9];
        let rewritten = rewrite_album_art_payload(&original, &replacement).unwrap();
        assert_eq!(rewritten, [0x80, 0x03, 0x0A, 0x01, b'A', 0x22, 0x0A, 0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 9, 9, 0x30, 0x0A]);
    }
}
