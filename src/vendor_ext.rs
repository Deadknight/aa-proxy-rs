use crate::mitm::protos::{Service, ServiceDiscoveryResponse, VendorExtensionService};
use crate::mitm::{
    ModifyContext, Packet, PacketAction, Result, ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST,
};
use crate::web::AppState;
use log::{info, warn};
use serde::{Deserialize, Serialize};

pub(crate) const OUR_VEC_SERVICE_NAME: &str = "aaproxy_companion";
pub(crate) const OUR_VEC_PACKAGE: &str = "com.github.deadknight.aaproxycompanion";

const VEC_APP_VERSION: u8 = 0x01;
const VEC_OP_PING: u8 = 0x01;
const VEC_OP_GET_STATUS: u8 = 0x02;
const VEC_OP_ECHO: u8 = 0x03;
const VEC_OP_REST_CALL: u8 = 0x04;

const VEC_OP_PONG: u8 = 0x81;
const VEC_OP_STATUS: u8 = 0x82;
const VEC_OP_ECHO_REPLY: u8 = 0x83;
const VEC_OP_REST_CALL_REPLY: u8 = 0x85;
const VEC_OP_REST_CALL_RESULT: u8 = 0x86;

const VEC_OP_ERROR: u8 = 0xFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VecChannelState {
    Opened,
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

pub(crate) fn vendor_extension_service_id(msg: &ServiceDiscoveryResponse) -> Option<u8> {
    msg.services
        .iter()
        .find(|svc| {
            svc.vendor_extension_service
                .as_ref()
                .map(|ves| ves.service_name() == OUR_VEC_SERVICE_NAME)
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
    ves.set_service_name(OUR_VEC_SERVICE_NAME.to_string());
    ves.package_white_list.push(OUR_VEC_PACKAGE.to_string());

    service.vendor_extension_service = protobuf::MessageField::some(ves);
    msg.services.push(service);

    let service_id = next_service_id as u8;
    ctx.vendor_service_ids.insert(service_id);

    Some(service_id)
}

fn build_vendor_app_reply(channel: u8, opcode: u8, payload: Vec<u8>) -> Packet {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(VEC_APP_VERSION);
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

fn build_error_reply(channel: u8, message: impl Into<String>) -> Packet {
    let message = message.into();
    warn!("VEC error: {}", message);
    build_vendor_app_reply(channel, VEC_OP_ERROR, message.into_bytes())
}

#[derive(Debug, Deserialize, Serialize)]
struct VecRestCall {
    method: String,
    path: String,
    body: String,
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

pub(crate) async fn handle_vendor_ws_event_tx(ctx: ModifyContext, state: AppState) {
    
}

pub(crate) async fn handle_vendor_channel_packet(
    pkt: &mut Packet,
    ctx: &mut ModifyContext,
) -> Result<PacketAction> {
    let state = ctx.vendor_channel_states.get(&pkt.channel).copied();

    info!(
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

    if version != VEC_APP_VERSION {
        warn!(
            "VEC unsupported app version={} opcode={:#04x} channel={:#04x}",
            version, opcode, pkt.channel
        );

        *pkt = build_error_reply(pkt.channel, format!("unsupported version {}", version));
        return Ok(PacketAction::SendBack);
    }

    match opcode {
        VEC_OP_PING => {
            info!(
                "VEC PING received channel={:#04x} payload={:02X?}",
                pkt.channel, body
            );

            *pkt = build_vendor_app_reply(pkt.channel, VEC_OP_PONG, body);
            Ok(PacketAction::SendBack)
        }
        VEC_OP_GET_STATUS => {
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

            *pkt = build_vendor_app_reply(pkt.channel, VEC_OP_STATUS, status.into_bytes());
            Ok(PacketAction::SendBack)
        }
        VEC_OP_ECHO => {
            info!(
                "VEC ECHO received channel={:#04x} payload_len={}",
                pkt.channel,
                body.len()
            );

            *pkt = build_vendor_app_reply(pkt.channel, VEC_OP_ECHO_REPLY, body);
            Ok(PacketAction::SendBack)
        }
        VEC_OP_REST_CALL => {
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
                    rest_call_blocking(rest_call.method, rest_call.path, rest_call.body)
                })
                .await
                {
                    Ok(result_call) => result_call,
                    Err(e) => {
                        format!(
                            r#"{{"ok":false,"error":"rest task failed: {}"}}"#,
                            e
                        )
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

                let reply = build_vendor_app_reply(
                    channel,
                    VEC_OP_REST_CALL_RESULT,
                    payload.into_bytes(),
                );

                if let Err(e) = tx.send(reply).await {
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

            *pkt = build_vendor_app_reply(
                pkt.channel,
                VEC_OP_REST_CALL_REPLY,
                payload.into_bytes(),
            );

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

pub fn rest_call_blocking(method: String, path: String, body: String) -> String {
    let path = path.trim();

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

    let url = format!("http://127.0.0.1{}", path);

    let result = match method.as_str() {
        "GET" => ureq::get(&url).call(),

        "POST" => ureq::post(&url)
            .set("content-type", "application/json")
            .send_string(&body),

        _ => {
            return r#"{"ok":false,"status":405,"error":"unsupported method"}"#.to_string();
        }
    };

    match result {
        Ok(response) => {
            let status = response.status();

            let text = response.into_string().unwrap_or_else(|err| {
                format!(
                    r#"{{"ok":false,"error":"failed to read response: {}"}}"#,
                    err
                )
            });

            format!(
                r#"{{"ok":true,"status":{},"body":{}}}"#,
                status,
                serde_json::to_string(&text).unwrap_or_else(|_| "\"\"".to_string())
            )
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