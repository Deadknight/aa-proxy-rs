use crate::config::AppConfig;
use crate::config_types::HexdumpLevel;
use crate::mitm::protos::ControlMessageType;
use crate::mitm::protos::ControlMessageType::*;
use crate::mitm::protos::*;
use crate::mitm::{get_name, ModifyContext, Packet, ProxyType, Result};
use log::{debug, info, log_enabled, Level};
use protobuf::text_format::print_to_string_pretty;
use protobuf::{Enum, Message, MessageDyn};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PacketDebugServiceKind {
    Unknown,
    Control,
    SensorSource,
    MediaSink,
    InputSource,
    MediaSource,
    Bluetooth,
    Radio,
    NavigationStatus,
    MediaPlaybackStatus,
    PhoneStatus,
    MediaBrowser,
    VendorExtension,
    GenericNotification,
    WifiProjection,
    CarProperty,
}

impl PacketDebugServiceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Control => "control",
            Self::SensorSource => "sensor_source",
            Self::MediaSink => "media_sink",
            Self::InputSource => "input_source",
            Self::MediaSource => "media_source",
            Self::Bluetooth => "bluetooth",
            Self::Radio => "radio",
            Self::NavigationStatus => "navigation_status",
            Self::MediaPlaybackStatus => "media_playback_status",
            Self::PhoneStatus => "phone_status",
            Self::MediaBrowser => "media_browser",
            Self::VendorExtension => "vendor_extension",
            Self::GenericNotification => "generic_notification",
            Self::WifiProjection => "wifi_projection",
            Self::CarProperty => "car_property",
        }
    }
}

fn split_filter_tokens(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(|c| c == ',' || c == ';' || c == ' ' || c == '\n' || c == '\t')
        .map(|part| part.trim().to_ascii_lowercase())
        .filter(|part| !part.is_empty())
}

fn parse_filter_u8(value: &str) -> Option<u8> {
    let token = value.trim();
    if token.is_empty() {
        return None;
    }

    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16).ok()
    } else {
        token.parse::<u8>().ok()
    }
}

fn parse_filter_u16(value: &str) -> Option<u16> {
    let token = value.trim();
    if token.is_empty() {
        return None;
    }

    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16).ok()
    } else {
        token.parse::<u16>().ok()
    }
}

fn list_contains_u8(list: &str, value: u8) -> bool {
    split_filter_tokens(list).any(|token| parse_filter_u8(&token) == Some(value))
}

fn list_contains_u16(list: &str, value: u16) -> bool {
    split_filter_tokens(list).any(|token| parse_filter_u16(&token) == Some(value))
}

fn hexdump_stage_token(stage: HexdumpLevel) -> &'static str {
    match stage {
        HexdumpLevel::Disabled => "disabled",
        HexdumpLevel::DecryptedInput => "decrypted_input",
        HexdumpLevel::RawInput => "raw_input",
        HexdumpLevel::DecryptedOutput => "decrypted_output",
        HexdumpLevel::RawOutput => "raw_output",
        HexdumpLevel::All => "all",
    }
}

fn stage_matches_filter(filter: &str, stage: HexdumpLevel) -> bool {
    let wanted = hexdump_stage_token(stage);
    split_filter_tokens(filter).any(|token| {
        token == wanted
            || token == "all"
            || token.replace('-', "_") == wanted
            || token.replace('-', "_") == wanted.replace('_', "")
            || token.eq_ignore_ascii_case(&format!("{:?}", stage))
    })
}

fn proxy_matches_filter(filter: &str, proxy_type: ProxyType) -> bool {
    match filter.trim().to_ascii_lowercase().as_str() {
        "" | "both" | "all" | "any" => true,
        "hu" | "headunit" | "head_unit" | "head-unit" => proxy_type == ProxyType::HeadUnit,
        "md" | "mobile" | "mobiledevice" | "mobile_device" | "mobile-device" => {
            proxy_type == ProxyType::MobileDevice
        }
        _ => true,
    }
}

fn service_kind_matches_filter(filter: &str, kind: PacketDebugServiceKind) -> bool {
    let wanted = kind.as_str();
    split_filter_tokens(filter).any(|token| {
        token == wanted
            || token == "all"
            || token == "any"
            || token == wanted.replace('_', "")
            || match kind {
                PacketDebugServiceKind::Control => {
                    matches!(token.as_str(), "control_channel" | "control")
                }
                PacketDebugServiceKind::SensorSource => {
                    matches!(token.as_str(), "sensor" | "sensor_source_channel")
                }
                PacketDebugServiceKind::MediaSink => matches!(
                    token.as_str(),
                    "sink" | "media_sink_service" | "media_sink_service_channel"
                ),
                PacketDebugServiceKind::InputSource => matches!(
                    token.as_str(),
                    "input" | "input_source_service" | "input_source_service_channel"
                ),
                PacketDebugServiceKind::MediaSource => matches!(
                    token.as_str(),
                    "source" | "media_source_service" | "media_source_service_channel"
                ),
                PacketDebugServiceKind::Bluetooth => matches!(
                    token.as_str(),
                    "bt" | "bluetooth_service" | "bluetooth_service_channel"
                ),
                PacketDebugServiceKind::Radio => {
                    matches!(token.as_str(), "radio_service" | "radio_service_channel")
                }
                PacketDebugServiceKind::NavigationStatus => matches!(
                    token.as_str(),
                    "nav"
                        | "navigation"
                        | "navigation_status_service"
                        | "navigation_status_service_channel"
                ),
                PacketDebugServiceKind::MediaPlaybackStatus => matches!(
                    token.as_str(),
                    "media_playback"
                        | "media_playback_service"
                        | "media_playback_status_service_channel"
                ),
                PacketDebugServiceKind::PhoneStatus => matches!(
                    token.as_str(),
                    "phone" | "phone_status_service" | "phone_status_service_channel"
                ),
                PacketDebugServiceKind::MediaBrowser => matches!(
                    token.as_str(),
                    "browser" | "media_browser_service" | "media_browser_service_channel"
                ),
                PacketDebugServiceKind::VendorExtension => matches!(
                    token.as_str(),
                    "vendor"
                        | "vec"
                        | "vendor_extension_service"
                        | "vendor_extension_service_channel"
                ),
                PacketDebugServiceKind::GenericNotification => matches!(
                    token.as_str(),
                    "notification"
                        | "generic_notification_service"
                        | "generic_notification_service_channel"
                ),
                PacketDebugServiceKind::WifiProjection => matches!(
                    token.as_str(),
                    "wifi" | "wifi_projection_service" | "wifi_projection_service_channel"
                ),
                PacketDebugServiceKind::CarProperty => matches!(
                    token.as_str(),
                    "car_property_service" | "car_property_service_channel"
                ),
                PacketDebugServiceKind::Unknown => token == "unknown",
            }
    })
}

fn pkt_debug_service_kind_for_service(svc: &Service) -> PacketDebugServiceKind {
    if svc.sensor_source_service.is_some() {
        PacketDebugServiceKind::SensorSource
    } else if svc.media_sink_service.is_some() {
        PacketDebugServiceKind::MediaSink
    } else if svc.input_source_service.is_some() {
        PacketDebugServiceKind::InputSource
    } else if svc.media_source_service.is_some() {
        PacketDebugServiceKind::MediaSource
    } else if svc.bluetooth_service.is_some() {
        PacketDebugServiceKind::Bluetooth
    } else if svc.radio_service.is_some() {
        PacketDebugServiceKind::Radio
    } else if svc.navigation_status_service.is_some() {
        PacketDebugServiceKind::NavigationStatus
    } else if svc.media_playback_service.is_some() {
        PacketDebugServiceKind::MediaPlaybackStatus
    } else if svc.phone_status_service.is_some() {
        PacketDebugServiceKind::PhoneStatus
    } else if svc.media_browser_service.is_some() {
        PacketDebugServiceKind::MediaBrowser
    } else if svc.vendor_extension_service.is_some() {
        PacketDebugServiceKind::VendorExtension
    } else if svc.generic_notification_service.is_some() {
        PacketDebugServiceKind::GenericNotification
    } else if svc.wifi_projection_service.is_some() {
        PacketDebugServiceKind::WifiProjection
    } else {
        PacketDebugServiceKind::Unknown
    }
}

pub fn update_debug_channel_kinds(ctx: &mut ModifyContext, msg: &ServiceDiscoveryResponse) {
    ctx.debug_channel_kinds.clear();
    ctx.debug_channel_kinds
        .insert(0, PacketDebugServiceKind::Control);

    for svc in msg.services.iter() {
        let Ok(channel) = u8::try_from(svc.id()) else {
            continue;
        };
        ctx.debug_channel_kinds
            .insert(channel, pkt_debug_service_kind_for_service(svc));
    }
}

fn pkt_debug_service_kind(
    pkt: &Packet,
    debug_channel_kinds: Option<&HashMap<u8, PacketDebugServiceKind>>,
) -> PacketDebugServiceKind {
    if pkt.channel == 0 {
        return PacketDebugServiceKind::Control;
    }

    debug_channel_kinds
        .and_then(|kinds| kinds.get(&pkt.channel).copied())
        .unwrap_or(PacketDebugServiceKind::Unknown)
}

fn pkt_debug_filter_matches(
    proxy_type: ProxyType,
    hexdump: HexdumpLevel,
    pkt: &Packet,
    message_id: u16,
    service_kind: PacketDebugServiceKind,
    cfg: &AppConfig,
) -> bool {
    if !cfg.pkt_debug_filter_enabled {
        return true;
    }

    if !proxy_matches_filter(&cfg.pkt_debug_filter_proxy, proxy_type) {
        return false;
    }

    if !cfg.pkt_debug_filter_stages.trim().is_empty()
        && !stage_matches_filter(&cfg.pkt_debug_filter_stages, hexdump)
    {
        return false;
    }

    if !cfg.pkt_debug_filter_service_kinds.trim().is_empty()
        && !service_kind_matches_filter(&cfg.pkt_debug_filter_service_kinds, service_kind)
    {
        return false;
    }

    if !cfg.pkt_debug_filter_channels.trim().is_empty()
        && !list_contains_u8(&cfg.pkt_debug_filter_channels, pkt.channel)
    {
        return false;
    }

    if !cfg.pkt_debug_filter_exclude_channels.trim().is_empty()
        && list_contains_u8(&cfg.pkt_debug_filter_exclude_channels, pkt.channel)
    {
        return false;
    }

    if !cfg.pkt_debug_filter_message_ids.trim().is_empty()
        && !list_contains_u16(&cfg.pkt_debug_filter_message_ids, message_id)
    {
        return false;
    }

    if !cfg.pkt_debug_filter_exclude_message_ids.trim().is_empty()
        && list_contains_u16(&cfg.pkt_debug_filter_exclude_message_ids, message_id)
    {
        return false;
    }

    true
}

fn format_packet_for_debug(pkt: &Packet, max_payload_bytes: Option<usize>) -> String {
    let payload_len = pkt.payload.len();
    let shown_len = max_payload_bytes
        .filter(|max| *max > 0)
        .map(|max| payload_len.min(max))
        .unwrap_or(payload_len);
    let truncated = shown_len < payload_len;

    let mut out = String::new();
    out.push_str("packet dump:\n");
    out.push_str(&format!(" channel: {:02X}\n", pkt.channel));
    out.push_str(&format!(" flags: {:02X}\n", pkt.flags));
    out.push_str(&format!(" final length: {:04X?}\n", pkt.final_length));
    out.push_str(&format!(" payload length: {}\n", payload_len));
    out.push_str(&format!(" payload: {:02X?}", &pkt.payload[..shown_len]));
    if truncated {
        out.push_str(&format!(
            "\n ... truncated {} byte(s)",
            payload_len - shown_len
        ));
    }
    out
}

/// shows packet/message contents as pretty string for debug
pub async fn pkt_debug(
    proxy_type: ProxyType,
    hexdump: HexdumpLevel,
    hex_requested: HexdumpLevel,
    pkt: &Packet,
    cfg: &AppConfig,
    debug_channel_kinds: Option<&HashMap<u8, PacketDebugServiceKind>>,
) -> Result<()> {
    // Keep packet debug independent from global debug logging.
    // - debug=true: old behavior, pkt_debug lines use DEBUG level.
    // - pkt_debug=true: packet debug is emitted at INFO level even when debug=false,
    //   so enabling packet logs does not enable every other debug!() message.
    let standalone_pkt_debug = cfg.pkt_debug;
    if !standalone_pkt_debug && !log_enabled!(Level::Debug) {
        return Ok(());
    }

    let emit_pkt_debug = |line: String| {
        if standalone_pkt_debug {
            info!("{}", line);
        } else {
            debug!("{}", line);
        }
    };

    // if for some reason we have too small packet, bail out
    if pkt.payload.len() < 2 {
        return Ok(());
    }
    // message_id is the first 2 bytes of payload
    let message_id: u16 = u16::from_be_bytes(pkt.payload[0..=1].try_into()?);

    let service_kind = pkt_debug_service_kind(pkt, debug_channel_kinds);
    if !pkt_debug_filter_matches(proxy_type, hexdump, pkt, message_id, service_kind, cfg) {
        return Ok(());
    }

    // trying to obtain an Enum from message_id
    let control = ControlMessageType::from_i32(message_id.into());
    emit_pkt_debug(format!(
        "message_id = {:04X}, {:?}, channel={:#04x}, service_kind={}",
        message_id,
        control,
        pkt.channel,
        service_kind.as_str()
    ));

    if hex_requested >= hexdump {
        let max_payload_bytes = if cfg.pkt_debug_filter_enabled {
            Some(cfg.pkt_debug_filter_max_payload_bytes)
        } else {
            None
        };
        emit_pkt_debug(format!(
            "{} {:?} {}",
            get_name(proxy_type),
            hexdump,
            format_packet_for_debug(pkt, max_payload_bytes)
        ));
    }

    if cfg.pkt_debug_filter_enabled && !cfg.pkt_debug_filter_pretty_proto {
        return Ok(());
    }

    // parsing data
    let data = &pkt.payload[2..]; // start of message data
    let message: &dyn MessageDyn = match control.unwrap_or(MESSAGE_UNEXPECTED_MESSAGE) {
        MESSAGE_BYEBYE_REQUEST => &ByeByeRequest::parse_from_bytes(data)?,
        MESSAGE_BYEBYE_RESPONSE => &ByeByeResponse::parse_from_bytes(data)?,
        MESSAGE_AUTH_COMPLETE => &AuthResponse::parse_from_bytes(data)?,
        MESSAGE_SERVICE_DISCOVERY_REQUEST => &ServiceDiscoveryRequest::parse_from_bytes(data)?,
        MESSAGE_SERVICE_DISCOVERY_RESPONSE => &ServiceDiscoveryResponse::parse_from_bytes(data)?,
        MESSAGE_SERVICE_DISCOVERY_UPDATE => &ServiceDiscoveryUpdate::parse_from_bytes(data)?,
        MESSAGE_PING_REQUEST => &PingRequest::parse_from_bytes(data)?,
        MESSAGE_PING_RESPONSE => &PingResponse::parse_from_bytes(data)?,
        MESSAGE_NAV_FOCUS_REQUEST => &NavFocusRequestNotification::parse_from_bytes(data)?,
        MESSAGE_CHANNEL_OPEN_RESPONSE => &ChannelOpenResponse::parse_from_bytes(data)?,
        MESSAGE_CHANNEL_OPEN_REQUEST => &ChannelOpenRequest::parse_from_bytes(data)?,
        MESSAGE_AUDIO_FOCUS_REQUEST => &AudioFocusRequestNotification::parse_from_bytes(data)?,
        MESSAGE_AUDIO_FOCUS_NOTIFICATION => &AudioFocusNotification::parse_from_bytes(data)?,
        _ => return Ok(()),
    };
    // show pretty string from the message
    emit_pkt_debug(print_to_string_pretty(message));

    Ok(())
}
