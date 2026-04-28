use crate::mitm::protos::KeyCode::{self, *};
use crate::mitm::protos::{InputMessageId, InputReport};
use crate::mitm::send_key_event;
use crate::mitm::{Packet, PacketAction};
use protobuf::{Enum, Message};
use simplelog::*;
use std::time::Instant;
use tokio::sync::mpsc::Sender;

// module name for logging engine
const NAME: &str = "<i><bright-black> hu_input: </>";

/// Threshold in milliseconds between a short press and a long press.
const LONG_PRESS_THRESHOLD_MS: u128 = 150;

/// Set of key codes that the hook intercepts.
/// Only media navigation keys are handled — all others pass through untouched.
const INTERCEPTED_KEYS: &[KeyCode] = &[
    KEYCODE_MEDIA_NEXT,
    KEYCODE_MEDIA_PREVIOUS,
    KEYCODE_MEDIA_FAST_FORWARD,
    KEYCODE_MEDIA_REWIND,
];

/// Keys that are always dropped (fast-forward / rewind), regardless of press duration.
/// They are never reinjected.
const ALWAYS_DROP_KEYS: &[KeyCode] = &[KEYCODE_MEDIA_FAST_FORWARD, KEYCODE_MEDIA_REWIND];

/// Per-key press state tracked across packets.
#[derive(Default)]
pub struct HuInputState {
    pressed_at: Option<Instant>,
}

/// Processes a single `InputReport` packet coming from the Head Unit.
///
/// Returns the [`PacketAction`] that the caller should apply to the packet.
/// For `PacketAction::Forward` the packet content may have been left unchanged
/// or rewritten by this function; the caller must not inspect `pkt.payload`
/// to decide whether to forward — the action variant is authoritative.
///
/// `hu_tx`       — channel used to re-inject synthetic key events back toward the HU.
/// `input_ch`    — the AA input channel number (needed when re-injecting).
/// `handler_cmd` — optional shell command configured via `hu_button_handler`.
///                 When `Some`, long-press events are dispatched to it.
pub async fn handle_hu_input(
    pkt: &mut Packet,
    state: &mut HuInputState,
    hu_tx: Option<&Sender<Packet>>,
    input_ch: u8,
    handler_cmd: Option<&str>,
) -> PacketAction {
    let message_id: i32 = match pkt.payload.get(0..2) {
        Some(bytes) => u16::from_be_bytes(bytes.try_into().unwrap()) as i32,
        None => return PacketAction::Forward,
    };

    if InputMessageId::from_i32(message_id) != Some(InputMessageId::INPUT_MESSAGE_INPUT_REPORT) {
        return PacketAction::Forward;
    }

    let data = &pkt.payload[2..];
    let report = match InputReport::parse_from_bytes(data) {
        Ok(r) => r,
        Err(e) => {
            warn!("{} failed to parse InputReport: {:?}", NAME, e);
            return PacketAction::Forward;
        }
    };

    let key_event = match report.key_event.as_ref() {
        Some(ke) => ke,
        None => return PacketAction::Forward,
    };

    for key in key_event.keys.iter() {
        let keycode = match key.keycode {
            Some(c) => c,
            None => continue,
        };

        // Only process keys we care about; everything else passes through.
        let key_enum = KeyCode::from_i32(keycode as i32);
        if !key_enum.map_or(false, |k| INTERCEPTED_KEYS.contains(&k)) {
            return PacketAction::Forward;
        }

        // Fast-forward / rewind: always drop, never reinject.
        if key_enum.map_or(false, |k| ALWAYS_DROP_KEYS.contains(&k)) {
            info!("{} dropping {:?} (always-drop key)", NAME, key_enum);
            return PacketAction::Drop;
        }

        // Next / previous: distinguish short press vs long press.
        match key.down {
            Some(true) => {
                // Record press timestamp, swallow the DOWN event.
                state.pressed_at = Some(Instant::now());
                info!("{} {:?} DOWN — recording press time", NAME, key_enum);
                return PacketAction::Drop;
            }

            Some(false) => {
                let elapsed_ms = state
                    .pressed_at
                    .take()
                    .map(|t| t.elapsed().as_millis())
                    .unwrap_or(0);

                if elapsed_ms >= LONG_PRESS_THRESHOLD_MS {
                    // Long press → dispatch to external handler script (if configured).
                    info!(
                        "{} {:?} long press ({} ms) → dispatching to handler",
                        NAME, key_enum, elapsed_ms
                    );
                    dispatch_to_handler(handler_cmd, keycode, elapsed_ms);
                } else {
                    // Short press → reinject a clean DOWN+UP click.
                    info!(
                        "{} {:?} short press ({} ms) → reinjecting click",
                        NAME, key_enum, elapsed_ms
                    );
                    if let Some(tx) = hu_tx {
                        let _ = send_key_event(tx.clone(), input_ch, keycode).await;
                    }
                }

                // Either way, drop the original UP event; we handled it above.
                return PacketAction::Drop;
            }

            None => {
                // Unknown state — drop defensively.
                warn!("{} {:?} with key.down=None — dropping", NAME, key_enum);
                return PacketAction::Drop;
            }
        }
    }

    PacketAction::Forward
}

/// Spawns the configured handler script with the key code and elapsed time as arguments.
///
/// The command string is split on whitespace (shell-word rules), so arguments
/// embedded in `handler_cmd` are supported (e.g. `/data/bin/my-script --mode aa`).
///
/// The process is fire-and-forget: errors are logged but do not propagate.
fn dispatch_to_handler(handler_cmd: Option<&str>, keycode: u32, elapsed_ms: u128) {
    let cmd_str = match handler_cmd {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            debug!(
                "{} no hu_button_handler configured, long press ignored",
                NAME
            );
            return;
        }
    };

    let tokens = match shell_words::split(cmd_str) {
        Ok(t) if !t.is_empty() => t,
        Ok(_) => {
            warn!("{} hu_button_handler is an empty string", NAME);
            return;
        }
        Err(e) => {
            error!("{} failed to parse hu_button_handler: {:?}", NAME, e);
            return;
        }
    };

    let program = &tokens[0];
    let mut args: Vec<String> = tokens[1..].to_vec();
    args.push(keycode.to_string());
    args.push(elapsed_ms.to_string());

    match std::process::Command::new(program).args(&args).spawn() {
        Ok(_) => info!("{} dispatched long press: {} {:?}", NAME, program, args),
        Err(e) => error!("{} failed to spawn handler '{}': {:?}", NAME, program, e),
    }
}
