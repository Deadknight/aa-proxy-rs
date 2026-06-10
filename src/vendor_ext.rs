use crate::mitm::protos::{Service, ServiceDiscoveryResponse, VendorExtensionService};
use crate::mitm::{
    ModifyContext, Packet, PacketAction, Result, ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST,
};
use crate::packet_fragment::{
    fragment_plain_payload, openauto_continuation_fragment_payload_bytes,
    DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES, PlainPayloadFragmentOptions,
};
#[cfg(feature = "wasm-scripting")]
use crate::script_wasm::{LoadedScript, ScriptRegistry};
use crate::web::ServerEvent;
use crate::companion_protocol::{
    COMPANION_APP_VERSION, COMPANION_OP_ECHO, COMPANION_OP_ECHO_REPLY,
    COMPANION_OP_ERROR, COMPANION_OP_GET_STATUS, COMPANION_OP_ON_SCRIPT_EVENT,
    COMPANION_OP_ON_TOPIC_EVENT, COMPANION_OP_PING, COMPANION_OP_PONG,
    COMPANION_OP_REST_CALL, COMPANION_OP_REST_CALL_REPLY,
    COMPANION_OP_REST_CALL_RESULT, COMPANION_OP_REST_CALL_SYNC,
    COMPANION_OP_STATUS, COMPANION_OP_SUBSCRIBE_TOPIC_EVENT,
    COMPANION_OP_UNSUBSCRIBE_TOPIC_EVENT,
};
#[cfg(not(feature = "wasm-scripting"))]
type ScriptRegistry = ();
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use log::{debug, info, warn};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc::Sender, RwLock};
use tokio::task::JoinHandle;

pub(crate) const OUR_COMPANION_SERVICE_NAME: &str = "aaproxy_companion";
pub(crate) const OUR_COMPANION_PACKAGE: &str = "com.github.deadknight.aaproxycompanion";

// Use the same OpenAuto/aasdk-style plaintext split as dynamic packet
// rewriters: FIRST ~= 16120 bytes, continuation ~= 16124 bytes. The old
// 4 KiB VEC split turned large log responses into 100+ tiny AA frames and
// could overload/drop the channel while the phone was fetching logs.
const COMPANION_APP_FIRST_FRAGMENT_CHUNK_SIZE: usize = DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VecChannelState {
    Opened,
}

#[derive(Clone)]
pub(crate) struct VecTopicEventRuntime {
    pub(crate) ws_event_tx: broadcast::Sender<ServerEvent>,
    pub(crate) script_registry: Option<Arc<ScriptRegistry>>,
}

pub(crate) fn is_vendor_service_id(ctx: &ModifyContext, service_id: u8) -> bool {
    ctx.vendor_service_ids.contains(&service_id)
}

pub(crate) fn is_vendor_channel(ctx: &ModifyContext, channel: u8) -> bool {
    ctx.vendor_service_ids.contains(&channel) || ctx.vendor_channel_states.contains_key(&channel)
}

pub(crate) fn mark_vendor_channel_open(ctx: &mut ModifyContext, channel: u8) {
    ctx.vendor_channel_states
        .insert(channel, VecChannelState::Opened);
}

pub(crate) fn ensure_vendor_channel_open(ctx: &mut ModifyContext, channel: u8) {
    ctx.vendor_channel_states
        .entry(channel)
        .or_insert(VecChannelState::Opened);
}

pub(crate) struct VecTopicEventBridge {
    pub(crate) subscriptions: Arc<RwLock<HashSet<String>>>,
    task: JoinHandle<()>,
}

impl VecTopicEventBridge {
    fn new(channel: u8, tx: Sender<Packet>, runtime: VecTopicEventRuntime) -> Self {
        let subscriptions = Arc::new(RwLock::new(HashSet::new()));
        let task_subscriptions = subscriptions.clone();
        let mut ws_event_rx = runtime.ws_event_tx.subscribe();

        let task = tokio::spawn(async move {
            loop {
                match ws_event_rx.recv().await {
                    Ok(event) => {
                        let should_send = {
                            let subscriptions = task_subscriptions.read().await;
                            subscriptions.contains(&event.topic)
                        };

                        if !should_send {
                            continue;
                        }

                        let event = match run_wasm_vec_topic_hooks(
                            event.topic.clone(),
                            event.payload.clone(),
                            runtime.clone(),
                        )
                        .await
                        {
                            Ok(Some(true)) => {
                                // wasm handled it and already emitted a replacement event.
                                continue;
                            }
                            Ok(Some(false)) | Ok(None) => event,
                            Err(err) => {
                                warn!(
                                    "wasm VEC topic hook failed, forwarding original event: {:#}",
                                    err
                                );
                                event
                            }
                        };

                        let payload = VecTopicEvent {
                            topic: event.topic,
                            payload: event.payload,
                        };

                        let payload = match serde_json::to_string(&payload) {
                            Ok(payload) => payload.into_bytes(),
                            Err(e) => {
                                warn!("Failed to serialize VEC topic event: {}", e);
                                continue;
                            }
                        };

                        let reply = build_vendor_app_reply(channel, COMPANION_OP_ON_TOPIC_EVENT, payload);

                        if let Err(e) = tx.send(reply).await {
                            warn!("Failed to send VEC topic event to phone: {}", e);
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(
                            "Companion topic event bridge lagged on channel={:#04x}, skipped {} events",
                            channel, skipped
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("VEC topic event bus closed for channel={:#04x}", channel);
                        break;
                    }
                }
            }
        });

        Self {
            subscriptions,
            task,
        }
    }
}

impl Drop for VecTopicEventBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn ensure_vendor_topic_event_bridge(
    ctx: &mut ModifyContext,
    channel: u8,
    runtime: VecTopicEventRuntime,
) -> bool {
    if ctx.vendor_topic_event_bridges.contains_key(&channel) {
        return true;
    }

    let Some(tx) = ctx.hu_tx.clone() else {
        warn!(
            "Cannot start Companion topic event bridge for channel={:#04x}: hu_tx is missing",
            channel
        );
        return false;
    };

    info!("Starting Companion topic event bridge channel={:#04x}", channel);

    ctx.vendor_topic_event_bridges
        .insert(channel, VecTopicEventBridge::new(channel, tx, runtime));

    true
}

pub(crate) fn vendor_extension_service_id(msg: &ServiceDiscoveryResponse) -> Option<u8> {
    msg.services
        .iter()
        .find(|svc| {
            svc.vendor_extension_service
                .as_ref()
                .map(|ves| ves.service_name() == OUR_COMPANION_SERVICE_NAME)
                .unwrap_or(false)
        })
        .map(|svc| svc.id() as u8)
}

pub(crate) fn has_vendor_extension_service(msg: &ServiceDiscoveryResponse) -> bool {
    vendor_extension_service_id(msg).is_some()
}

pub(crate) fn add_vendor_extension_service(
    msg: &mut ServiceDiscoveryResponse,
    ctx: &mut ModifyContext,
) -> Option<u8> {
    if let Some(existing_service_id) = vendor_extension_service_id(msg) {
        ctx.vendor_service_ids.insert(existing_service_id);
        return None;
    }

    let next_service_id = msg.services.iter().map(|svc| svc.id()).max().unwrap_or(0) + 1;

    let mut service = Service::new();
    service.set_id(next_service_id);

    let mut ves = VendorExtensionService::new();
    ves.set_service_name(OUR_COMPANION_SERVICE_NAME.to_string());
    ves.package_white_list.push(OUR_COMPANION_PACKAGE.to_string());

    service.vendor_extension_service = protobuf::MessageField::some(ves);
    msg.services.push(service);

    let service_id = next_service_id as u8;
    ctx.vendor_service_ids.insert(service_id);

    Some(service_id)
}

fn build_vendor_app_reply(channel: u8, opcode: u8, payload: Vec<u8>) -> Packet {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(COMPANION_APP_VERSION);
    out.push(opcode);
    out.extend_from_slice(&payload);

    Packet {
        channel,
        // Custom vendor app-data frame. Do not set CONTROL here.
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload: out,
    }
}

fn build_vendor_app_reply_fragments(channel: u8, opcode: u8, payload: Vec<u8>) -> Vec<Packet> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(COMPANION_APP_VERSION);
    out.push(opcode);
    out.extend_from_slice(&payload);

    let first_chunk = COMPANION_APP_FIRST_FRAGMENT_CHUNK_SIZE;
    let continuation_chunk = openauto_continuation_fragment_payload_bytes(first_chunk);
    let total_len = out.len();

    let packets = fragment_plain_payload(
        &out,
        PlainPayloadFragmentOptions {
            channel,
            // Custom vendor app-data frame. Do not set CONTROL here.
            base_flags: ENCRYPTED,
            first_fragment_payload_bytes: first_chunk,
            continuation_fragment_payload_bytes: continuation_chunk,
            first_final_length: Some(total_len as u32),
        },
    );

    if packets.len() > 1 {
        let log_line = format!(
            "VEC reply fragmented channel={:#04x} opcode={:#04x} total_len={} chunks={} first_chunk={} continuation_chunk={}",
            channel,
            opcode,
            total_len,
            packets.len(),
            first_chunk,
            continuation_chunk
        );

        if total_len >= 128 * 1024 {
            info!("{}", log_line);
        } else {
            debug!("{}", log_line);
        }
    }

    packets
}

async fn send_vendor_app_reply_fragments(
    tx: Sender<Packet>,
    channel: u8,
    opcode: u8,
    payload: Vec<u8>,
) -> std::result::Result<(), tokio::sync::mpsc::error::SendError<Packet>> {
    for reply in build_vendor_app_reply_fragments(channel, opcode, payload) {
        tx.send(reply).await?;
    }

    Ok(())
}

fn build_error_reply(channel: u8, message: impl Into<String>) -> Packet {
    let message = message.into();
    warn!("VEC error: {}", message);
    build_vendor_app_reply(channel, COMPANION_OP_ERROR, message.into_bytes())
}

#[derive(Debug, Deserialize, Serialize)]
struct VecRestCall {
    method: String,
    path: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: String,
    #[serde(default)]
    body_base64: Option<String>,
}

impl VecRestCall {
    fn body_bytes(&self) -> std::result::Result<Vec<u8>, String> {
        match self.body_base64.as_deref() {
            Some(encoded) if !encoded.is_empty() => BASE64_STANDARD
                .decode(encoded)
                .map_err(|e| format!("invalid REST body_base64: {}", e)),
            _ => Ok(self.body.as_bytes().to_vec()),
        }
    }
}

fn should_forward_rest_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length" | "host" | "connection" | "transfer-encoding"
    )
}

#[derive(Debug, Deserialize, Serialize)]
struct VecRestCallStatus {
    request_id: String,
    status: i8,
}

#[derive(Debug, Deserialize, Serialize)]
struct VecRestCallResult {
    request_id: String,
    payload: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VecTopicSubscription {
    topic: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VecTopicEvent {
    topic: String,
    payload: String,
}

fn parse_json_body<T: DeserializeOwned>(
    body: Vec<u8>,
    op_name: &str,
) -> std::result::Result<T, String> {
    let body_str = String::from_utf8(body)
        .map_err(|e| format!("{} body is not valid UTF-8: {}", op_name, e))?;

    serde_json::from_str(&body_str)
        .map_err(|e| format!("Invalid {} JSON: {}; body={}", op_name, e, body_str))
}

fn build_topic_status_reply(
    channel: u8,
    status: &str,
    topic: String,
    receiver_count: Option<usize>,
) -> Packet {
    let payload = serde_json::json!({
        "ok": true,
        "status": status,
        "topic": topic,
        "receiver_count": receiver_count,
    })
    .to_string();

    build_vendor_app_reply(channel, COMPANION_OP_STATUS, payload.into_bytes())
}

#[cfg(not(feature = "wasm-scripting"))]
async fn run_wasm_vec_topic_hooks(
    _topic: String,
    _payload: String,
    _runtime: VecTopicEventRuntime,
) -> Result<Option<bool>> {
    Ok(None)
}

#[cfg(feature = "wasm-scripting")]
async fn run_wasm_vec_topic_hooks(
    topic: String,
    payload: String,
    runtime: VecTopicEventRuntime,
) -> Result<Option<bool>> {
    let Some(registry) = runtime.script_registry else {
        return Ok(None);
    };

    let loaded: Vec<LoadedScript> = registry.list_scripts();
    if loaded.is_empty() {
        return Ok(None);
    }

    for script in loaded {
        match script
            .engine
            .ws_script_handler(topic.clone(), payload.clone())
            .await
        {
            Ok((result_payload, _effects)) => {
                if !result_payload.is_empty() {
                    let _ = runtime.ws_event_tx.send(ServerEvent {
                        topic: topic.clone(),
                        payload: result_payload,
                    });

                    return Ok(Some(true));
                }
            }
            Err(err) => {
                warn!(
                    "wasm VEC topic hook runtime error [{}], forwarding original event: {:#}",
                    script.path.display(),
                    err
                );
            }
        }
    }

    Ok(Some(false))
}

pub(crate) async fn handle_vendor_channel_packet(
    pkt: &mut Packet,
    ctx: &mut ModifyContext,
    runtime: VecTopicEventRuntime,
) -> Result<PacketAction> {
    let state = ctx.vendor_channel_states.get(&pkt.channel).copied();

    debug!(
        "VEC app packet channel={:#04x} state={:?} flags={:#04x} len={} payload={:02X?}",
        pkt.channel,
        state,
        pkt.flags,
        pkt.payload.len(),
        pkt.payload
    );

    if pkt.payload.len() < 2 {
        warn!(
            "VEC app packet too short channel={:#04x} payload={:02X?}",
            pkt.channel, pkt.payload
        );

        *pkt = build_error_reply(pkt.channel, "short packet");
        return Ok(PacketAction::SendBack);
    }

    let version = pkt.payload[0];
    let opcode = pkt.payload[1];
    let body = pkt.payload[2..].to_vec();

    if version != COMPANION_APP_VERSION {
        warn!(
            "VEC unsupported app version={} opcode={:#04x} channel={:#04x}",
            version, opcode, pkt.channel
        );

        *pkt = build_error_reply(pkt.channel, format!("unsupported version {}", version));
        return Ok(PacketAction::SendBack);
    }

    match opcode {
        COMPANION_OP_PING => {
            info!(
                "VEC PING received channel={:#04x} payload={:02X?}",
                pkt.channel, body
            );

            *pkt = build_vendor_app_reply(pkt.channel, COMPANION_OP_PONG, body);
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_GET_STATUS => {
            let status = serde_json::json!({
                "ok": true,
                "channel": pkt.channel,
                "sensor_channel": ctx.sensor_channel,
                "input_channel": ctx.input_channel,
                "nav_channel": ctx.nav_channel,
                "audio_channels": &ctx.audio_channels,
            })
            .to_string();

            info!("VEC GET_STATUS received channel={:#04x}", pkt.channel);

            *pkt = build_vendor_app_reply(pkt.channel, COMPANION_OP_STATUS, status.into_bytes());
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_ECHO => {
            info!(
                "VEC ECHO received channel={:#04x} payload_len={}",
                pkt.channel,
                body.len()
            );

            *pkt = build_vendor_app_reply(pkt.channel, COMPANION_OP_ECHO_REPLY, body);
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_SUBSCRIBE_TOPIC_EVENT => {
            let subscription: VecTopicSubscription = match parse_json_body(body, "VEC subscribe") {
                Ok(v) => v,
                Err(e) => {
                    warn!("{}", e);
                    *pkt = build_error_reply(pkt.channel, e);
                    return Ok(PacketAction::SendBack);
                }
            };

            let topic = subscription.topic.trim().to_string();
            if topic.is_empty() {
                *pkt = build_error_reply(pkt.channel, "VEC subscribe topic is empty");
                return Ok(PacketAction::SendBack);
            }

            if !ensure_vendor_topic_event_bridge(ctx, pkt.channel, runtime) {
                *pkt = build_error_reply(
                    pkt.channel,
                    "Companion topic event bridge is not available for this channel",
                );
                return Ok(PacketAction::SendBack);
            }

            let Some(subscriptions) = ctx
                .vendor_topic_event_bridges
                .get(&pkt.channel)
                .map(|bridge| bridge.subscriptions.clone())
            else {
                *pkt = build_error_reply(
                    pkt.channel,
                    "Companion topic event bridge was not registered for this channel",
                );
                return Ok(PacketAction::SendBack);
            };

            subscriptions.write().await.insert(topic.clone());
            info!(
                "VEC subscribed channel={:#04x} topic={}",
                pkt.channel, topic
            );

            *pkt = build_topic_status_reply(pkt.channel, "subscribed", topic, None);
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_UNSUBSCRIBE_TOPIC_EVENT => {
            let subscription: VecTopicSubscription = match parse_json_body(body, "VEC unsubscribe")
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("{}", e);
                    *pkt = build_error_reply(pkt.channel, e);
                    return Ok(PacketAction::SendBack);
                }
            };

            let topic = subscription.topic.trim().to_string();
            if topic.is_empty() {
                *pkt = build_error_reply(pkt.channel, "VEC unsubscribe topic is empty");
                return Ok(PacketAction::SendBack);
            }

            if let Some(subscriptions) = ctx
                .vendor_topic_event_bridges
                .get(&pkt.channel)
                .map(|bridge| bridge.subscriptions.clone())
            {
                subscriptions.write().await.remove(&topic);
            }

            info!(
                "VEC unsubscribed channel={:#04x} topic={}",
                pkt.channel, topic
            );

            *pkt = build_topic_status_reply(pkt.channel, "unsubscribed", topic, None);
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_ON_SCRIPT_EVENT => {
            let event: VecTopicEvent = match parse_json_body(body, "VEC script event") {
                Ok(v) => v,
                Err(e) => {
                    warn!("{}", e);
                    *pkt = build_error_reply(pkt.channel, e);
                    return Ok(PacketAction::SendBack);
                }
            };

            let topic = event.topic.trim().to_string();
            if topic.is_empty() {
                *pkt = build_error_reply(pkt.channel, "VEC script event topic is empty");
                return Ok(PacketAction::SendBack);
            }

            let payload = event.payload;
            let receiver_count = match run_wasm_vec_topic_hooks(
                topic.clone(),
                payload.clone(),
                runtime.clone(),
            )
            .await
            {
                Ok(Some(true)) => {
                    // wasm handled it and already emitted a replacement event.
                    0
                }
                Ok(Some(false)) | Ok(None) => {
                    match runtime.ws_event_tx.send(ServerEvent {
                        topic: topic.clone(),
                        payload,
                    }) {
                        Ok(receiver_count) => receiver_count,
                        Err(e) => {
                            debug!(
                                "VEC script event had no active receivers channel={:#04x} topic={} error={}",
                                pkt.channel, topic, e
                            );
                            0
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        "wasm VEC script event hook failed, forwarding original event: {:#}",
                        err
                    );

                    match runtime.ws_event_tx.send(ServerEvent {
                        topic: topic.clone(),
                        payload,
                    }) {
                        Ok(receiver_count) => receiver_count,
                        Err(e) => {
                            debug!(
                                "VEC script event had no active receivers channel={:#04x} topic={} error={}",
                                pkt.channel, topic, e
                            );
                            0
                        }
                    }
                }
            };

            info!(
                "VEC published script event channel={:#04x} topic={} receiver_count={}",
                pkt.channel, topic, receiver_count
            );

            *pkt = build_topic_status_reply(pkt.channel, "published", topic, Some(receiver_count));
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_REST_CALL_SYNC => {
            let body_str = match String::from_utf8(body) {
                Ok(s) => s,
                Err(e) => {
                    warn!("VEC REST body is not valid UTF-8: {}", e);
                    *pkt = build_error_reply(
                        pkt.channel,
                        format!("VEC REST body is not valid UTF-8: {}", e),
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let rest_call: VecRestCall = match serde_json::from_str(&body_str) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Invalid VEC REST call JSON: {}; body={}", e, body_str);
                    *pkt = build_error_reply(
                        pkt.channel,
                        format!("Invalid VEC REST call JSON: {}", e),
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let _ = match ctx.hu_tx.clone() {
                Some(tx) => tx,
                None => {
                    *pkt = build_error_reply(
                        pkt.channel,
                        "VEC REST call cannot be processed because hu_tx is missing",
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let channel = pkt.channel;
            let result_call = rest_call_blocking_vec(rest_call, false);

            *pkt =
                build_vendor_app_reply(channel, COMPANION_OP_REST_CALL_RESULT, result_call.into_bytes());

            return Ok(PacketAction::SendBack);
        }
        COMPANION_OP_REST_CALL => {
            let body_str = match String::from_utf8(body) {
                Ok(s) => s,
                Err(e) => {
                    warn!("VEC REST body is not valid UTF-8: {}", e);
                    *pkt = build_error_reply(
                        pkt.channel,
                        format!("VEC REST body is not valid UTF-8: {}", e),
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let rest_call: VecRestCall = match serde_json::from_str(&body_str) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Invalid VEC REST call JSON: {}; body={}", e, body_str);
                    *pkt = build_error_reply(
                        pkt.channel,
                        format!("Invalid VEC REST call JSON: {}", e),
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let tx = match ctx.hu_tx.clone() {
                Some(tx) => tx,
                None => {
                    *pkt = build_error_reply(
                        pkt.channel,
                        "VEC REST call cannot be processed because hu_tx is missing",
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let channel = pkt.channel;
            let request_id = uuid::Uuid::new_v4().to_string();
            let request_id_for_task = request_id.clone();

            tokio::spawn(async move {
                let result_call = match tokio::task::spawn_blocking(move || {
                    rest_call_blocking_vec(rest_call, false)
                })
                .await
                {
                    Ok(result_call) => result_call,
                    Err(e) => {
                        format!(r#"{{"ok":false,"error":"rest task failed: {}"}}"#, e)
                    }
                };

                let result_payload = VecRestCallResult {
                    request_id: request_id_for_task,
                    payload: result_call,
                };

                let payload = match serde_json::to_string(&result_payload) {
                    Ok(json) => json,
                    Err(e) => {
                        warn!("Failed to serialize VEC REST call result: {}", e);

                        let reply = build_error_reply(
                            channel,
                            format!("Failed to serialize VEC REST call result: {}", e),
                        );

                        if let Err(send_err) = tx.send(reply).await {
                            warn!(
                                "Failed to send async VEC REST serialization error to phone: {}",
                                send_err
                            );
                        }

                        return;
                    }
                };

                if let Err(e) = send_vendor_app_reply_fragments(
                    tx,
                    channel,
                    COMPANION_OP_REST_CALL_RESULT,
                    payload.into_bytes(),
                )
                .await
                {
                    warn!("Failed to send async VEC REST result to phone: {}", e);
                }
            });

            let rest_call_status = VecRestCallStatus {
                request_id,
                status: 1,
            };

            let payload = match serde_json::to_string(&rest_call_status) {
                Ok(json) => json,
                Err(e) => {
                    warn!("Failed to serialize VEC REST call status: {}", e);
                    *pkt = build_error_reply(
                        pkt.channel,
                        format!("Failed to serialize VEC REST call status: {}", e),
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            *pkt =
                build_vendor_app_reply(pkt.channel, COMPANION_OP_REST_CALL_REPLY, payload.into_bytes());

            Ok(PacketAction::SendBack)
        }
        _ => {
            warn!(
                "VEC unknown app opcode={:#04x} channel={:#04x} payload={:02X?}",
                opcode, pkt.channel, body
            );

            *pkt = build_error_reply(pkt.channel, format!("unknown opcode 0x{:02x}", opcode));
            Ok(PacketAction::SendBack)
        }
    }
}

fn rest_call_blocking_vec(rest_call: VecRestCall, whitelist: bool) -> String {
    let body_bytes = match rest_call.body_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            return serde_json::json!({
                "ok": false,
                "status": 400,
                "error": err,
            })
            .to_string();
        }
    };

    rest_call_blocking_bytes(
        rest_call.method,
        rest_call.path,
        rest_call.headers,
        body_bytes,
        whitelist,
    )
}

pub fn rest_call_blocking(method: String, path: String, body: String, whitelist: bool) -> String {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    rest_call_blocking_bytes(method, path, headers, body.into_bytes(), whitelist)
}

fn rest_call_blocking_bytes(
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body_bytes: Vec<u8>,
    whitelist: bool,
) -> String {
    let path = path.trim();

    if whitelist {
        //Whitelist calls
        match (method.as_str(), path) {
            ("POST", "/battery")
            | ("POST", "/odometer")
            | ("POST", "/tire-pressure")
            | ("POST", "/inject_event")
            | ("POST", "/inject_rotary")
            | ("GET", "/speed")
            | ("GET", "/battery-status")
            | ("GET", "/odometer-status")
            | ("GET", "/tire-pressure-status") => {}

            _ => {
                return format!(
                    r#"{{"ok":false,"status":403,"error":"route not allowed from script: {} {}"}}"#,
                    method, path
                );
            }
        }
    }

    let url = format!("http://127.0.0.1{}", path);

    let result = match method.as_str() {
        "GET" => {
            let mut req = ureq::get(&url);
            for (name, value) in &headers {
                if should_forward_rest_header(name) {
                    req = req.set(name, value);
                }
            }
            req.call()
        }

        "POST" | "PUT" | "PATCH" => {
            let mut req = match method.as_str() {
                "POST" => ureq::post(&url),
                "PUT" => ureq::put(&url),
                "PATCH" => ureq::patch(&url),
                _ => unreachable!(),
            };

            let has_content_type = headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-type"));

            for (name, value) in &headers {
                if should_forward_rest_header(name) {
                    req = req.set(name, value);
                }
            }

            if !has_content_type {
                req = req.set("content-type", "application/json");
            }

            req.send_bytes(&body_bytes)
        }

        _ => {
            return r#"{"ok":false,"status":405,"error":"unsupported method"}"#.to_string();
        }
    };

    match result {
        Ok(response) => {
            let status = response.status();

            let mut headers = serde_json::Map::new();
            for name in response.headers_names() {
                if let Some(value) = response.header(&name) {
                    headers.insert(name, serde_json::Value::String(value.to_string()));
                }
            }

            let mut body_bytes = Vec::new();
            if let Err(err) = response.into_reader().read_to_end(&mut body_bytes) {
                return serde_json::json!({
                    "ok": false,
                    "status": status,
                    "error": format!("failed to read response: {}", err),
                })
                .to_string();
            }

            let body_text = String::from_utf8(body_bytes.clone()).ok();
            let body_base64 = BASE64_STANDARD.encode(&body_bytes);

            let mut result = serde_json::json!({
                "ok": true,
                "status": status,
                "headers": headers,
                "body_base64": body_base64,
                "body_encoding": "base64",
            });

            if let Some(text) = body_text {
                result["body"] = serde_json::Value::String(text);
            }

            result.to_string()
        }

        Err(err) => {
            log::warn!("rest_call failed: {err}");

            format!(
                r#"{{"ok":false,"status":500,"error":{}}}"#,
                serde_json::to_string(&err.to_string())
                    .unwrap_or_else(|_| "\"request failed\"".to_string())
            )
        }
    }
}
