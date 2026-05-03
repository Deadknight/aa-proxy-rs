use crate::mitm::protos::{Service, ServiceDiscoveryResponse, VendorExtensionService};
use crate::mitm::{
    ModifyContext, Packet, PacketAction, Result, ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST,
};
use log::{info, warn};

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
const VEC_OP_REST_CALL_REPLY: u8 = 0x84;
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
    ctx.vendor_channel_states.insert(channel, VecChannelState::Opened);
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

        *pkt = build_vendor_app_reply(pkt.channel, VEC_OP_ERROR, b"short packet".to_vec());
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

        *pkt = build_vendor_app_reply(
            pkt.channel,
            VEC_OP_ERROR,
            format!("unsupported version {}", version).into_bytes(),
        );
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
                "audio_channels": ctx.audio_channels,
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
            warn!(
                "VEC REST_CALL received but not implemented channel={:#04x} payload={:02X?}",
                pkt.channel, body
            );

            *pkt = build_vendor_app_reply(
                pkt.channel,
                VEC_OP_REST_CALL_REPLY,
                b"REST_CALL not implemented".to_vec(),
            );
            Ok(PacketAction::SendBack)
        }
        _ => {
            warn!(
                "VEC unknown app opcode={:#04x} channel={:#04x} payload={:02X?}",
                opcode, pkt.channel, body
            );

            *pkt = build_vendor_app_reply(
                pkt.channel,
                VEC_OP_ERROR,
                format!("unknown opcode 0x{:02x}", opcode).into_bytes(),
            );
            Ok(PacketAction::SendBack)
        }
    }
}
