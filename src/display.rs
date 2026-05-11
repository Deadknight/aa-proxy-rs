use crate::config::AppConfig;
pub use crate::media_tap::{
    media_tcp_server, AudioStreamConfig, MediaSink, MediaStreamInfo, MediaStreamKind,
};
use crate::mitm::get_name;
use crate::mitm::protos::config::Status;
use crate::mitm::protos::Config as ProtoConfig;
use crate::mitm::protos::MediaMessageId::*;
use crate::mitm::protos::*;
use crate::mitm::ModifyContext;
use crate::mitm::Packet;
use crate::mitm::ProxyType;
use crate::mitm::{ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST, FRAME_TYPE_MASK};
use protobuf::Enum;
use protobuf::Message;
use simplelog::*;
use tokio::sync::mpsc::Sender;

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum InjectedMediaPhase {
    #[default]
    Idle,
    SetupSeen,
    FocusSent,
    Started,
    Streaming,
}

impl InjectedMediaPhase {
    fn can_stream(self) -> bool {
        matches!(self, Self::Started | Self::Streaming)
    }

    fn awaiting_focus(self) -> bool {
        matches!(self, Self::SetupSeen)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InjectedMediaState {
    phase: InjectedMediaPhase,
    session_id: i32,
    ack_counter: u32,
    last_flags: u8,
    trace_after_start: u16,
}

// // message related constants:
// pub const HEADER_LENGTH: usize = 4;
// pub const FRAME_TYPE_FIRST: u8 = 1 << 0;
// pub const FRAME_TYPE_LAST: u8 = 1 << 1;
// pub const FRAME_TYPE_MASK: u8 = FRAME_TYPE_FIRST | FRAME_TYPE_LAST;
// const _CONTROL: u8 = 1 << 2;
// pub const ENCRYPTED: u8 = 1 << 3;

#[derive(Clone, Copy)]
struct DisplayProfile {
    display_type: DisplayType,
    display_id: u32,
    codec_resolution: VideoCodecResolutionType,
    width_margin: u32,
    height_margin: u32,
    density: u32,
    viewing_distance: u32,
    touch_width: i32,
    touch_height: i32,
}

fn display_profiles(cfg: &AppConfig) -> Vec<DisplayProfile> {
    let mut profiles = Vec::new();
    let Some(display_types) = cfg.inject_display_types.0.as_ref() else {
        return profiles;
    };

    for display_type in display_types {
        match display_type {
            DisplayType::DISPLAY_TYPE_CLUSTER => profiles.push(DisplayProfile {
                display_type: DisplayType::DISPLAY_TYPE_CLUSTER,
                display_id: cfg.inject_cluster_display_id.into(),
                codec_resolution: cfg.inject_cluster_codec_resolution.0,
                width_margin: cfg.inject_cluster_width_margin.into(),
                height_margin: cfg.inject_cluster_height_margin.into(),
                density: if cfg.dpi > 0 {
                    cfg.dpi.into()
                } else {
                    cfg.inject_cluster_density.into()
                },
                viewing_distance: cfg.inject_cluster_viewing_distance.into(),
                touch_width: cfg.inject_cluster_touch_width.into(),
                touch_height: cfg.inject_cluster_touch_height.into(),
            }),
            DisplayType::DISPLAY_TYPE_AUXILIARY => profiles.push(DisplayProfile {
                display_type: DisplayType::DISPLAY_TYPE_AUXILIARY,
                display_id: cfg.inject_aux_display_id.into(),
                codec_resolution: VideoCodecResolutionType::VIDEO_1280x720,
                width_margin: cfg.inject_aux_width_margin.into(),
                height_margin: cfg.inject_aux_height_margin.into(),
                density: if cfg.dpi > 0 {
                    cfg.dpi.into()
                } else {
                    cfg.inject_aux_density.into()
                },
                viewing_distance: cfg.inject_aux_viewing_distance.into(),
                touch_width: cfg.inject_aux_touch_width.into(),
                touch_height: cfg.inject_aux_touch_height.into(),
            }),
            DisplayType::DISPLAY_TYPE_MAIN => {
                // Main display is expected from HU and is intentionally not synthesized.
            }
        }
    }

    profiles
}

fn has_video_display(msg: &ServiceDiscoveryResponse, display_type: DisplayType) -> bool {
    msg.services.iter().any(|svc| {
        !svc.media_sink_service.video_configs.is_empty()
            && svc.media_sink_service.display_type() == display_type
    })
}

fn has_input_display(msg: &ServiceDiscoveryResponse, display_id: u32) -> bool {
    msg.services.iter().any(|svc| {
        svc.input_source_service.is_some() && svc.input_source_service.display_id() == display_id
    })
}

fn next_service_id(msg: &ServiceDiscoveryResponse) -> i32 {
    msg.services.iter().map(|s| s.id()).max().unwrap_or(0) + 1
}

fn create_media_sink_service(id: i32, profile: DisplayProfile) -> Service {
    let mut margins = Insets::new();
    margins.set_top(profile.height_margin / 2);
    margins.set_bottom(profile.height_margin / 2);
    margins.set_left(profile.width_margin / 2);
    margins.set_right(profile.width_margin / 2);

    let mut ui_config = UiConfig::new();
    ui_config.margins = Some(margins).into();
    ui_config.content_insets = Some(Insets::new()).into();
    ui_config.stable_content_insets = Some(Insets::new()).into();
    ui_config.set_ui_theme(UiTheme::UI_THEME_AUTOMATIC);

    let mut video_cfg = VideoConfiguration::new();
    video_cfg.set_codec_resolution(profile.codec_resolution);
    video_cfg.set_frame_rate(VideoFrameRateType::VIDEO_FPS_30);
    video_cfg.set_width_margin(profile.width_margin);
    video_cfg.set_height_margin(profile.height_margin);
    video_cfg.set_density(profile.density);
    video_cfg.set_decoder_additional_depth(0);
    video_cfg.set_viewing_distance(profile.viewing_distance);
    video_cfg.set_pixel_aspect_ratio_e4(10000);
    video_cfg.set_real_density(profile.density);
    video_cfg.set_video_codec_type(MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP);
    video_cfg.ui_config = Some(ui_config).into();

    let mut sink = MediaSinkService::new();
    sink.set_available_type(MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP);
    sink.video_configs.push(video_cfg);
    sink.set_display_id(profile.display_id);
    sink.set_display_type(profile.display_type);

    let mut service = Service::new();
    service.set_id(id);
    service.media_sink_service = Some(sink).into();
    service
}

fn create_input_source_service(id: i32, profile: DisplayProfile) -> Service {
    let keycodes = match profile.display_type {
        DisplayType::DISPLAY_TYPE_CLUSTER => vec![19, 20, 21, 22, 23],
        DisplayType::DISPLAY_TYPE_AUXILIARY => {
            vec![3, 4, 5, 6, 84, 85, 87, 88, 126, 127, 65537, 65538, 65540]
        }
        DisplayType::DISPLAY_TYPE_MAIN => unreachable!("main input source must not be synthesized"),
    };

    let mut source = InputSourceService::new();
    source.keycodes_supported = keycodes;
    if profile.display_type == DisplayType::DISPLAY_TYPE_AUXILIARY {
        let mut touchscreen = input_source_service::TouchScreen::new();
        touchscreen.set_width(profile.touch_width);
        touchscreen.set_height(profile.touch_height);
        touchscreen.set_type(TouchScreenType::RESISTIVE);
        touchscreen.set_is_secondary(true);
        source.touchscreen.push(touchscreen);
    }
    source.set_display_id(profile.display_id);

    let mut service = Service::new();
    service.set_id(id);
    service.input_source_service = Some(source).into();
    service
}

pub fn add_display_services(msg: &mut ServiceDiscoveryResponse, cfg: &AppConfig) -> usize {
    if !cfg.mitm {
        return 0;
    }

    let mut added = 0usize;
    for profile in display_profiles(cfg) {
        if !has_video_display(msg, profile.display_type) {
            let id = next_service_id(msg);
            msg.services.push(create_media_sink_service(id, profile));
            added += 1;
        }

        if cfg.inject_add_input_sources && !has_input_display(msg, profile.display_id) {
            let id = next_service_id(msg);
            msg.services.push(create_input_source_service(id, profile));
            added += 1;
        }
    }

    added
}

fn injected_max_unacked(display_type: DisplayType) -> u32 {
    match display_type {
        DisplayType::DISPLAY_TYPE_CLUSTER => 1,
        DisplayType::DISPLAY_TYPE_AUXILIARY => 2,
        _ => 1,
    }
}

fn first_fragment_message_id(pkt: &Packet) -> Option<u16> {
    if pkt.payload.len() < 2 {
        return None;
    }

    match pkt.flags & FRAME_TYPE_MASK {
        f if f == FRAME_TYPE_FIRST || f == (FRAME_TYPE_FIRST | FRAME_TYPE_LAST) => {
            Some(u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]))
        }
        _ => None,
    }
}

fn rewrite_media_config_ready(pkt: &mut Packet, max_unacked: u32) -> Result<()> {
    let mut cfg = ProtoConfig::new();
    cfg.set_status(Status::STATUS_READY);
    cfg.set_max_unacked(max_unacked);
    cfg.configuration_indices.push(0);

    let mut payload = cfg.write_to_bytes()?;
    payload.insert(0, ((MEDIA_MESSAGE_CONFIG as u16) >> 8) as u8);
    payload.insert(1, ((MEDIA_MESSAGE_CONFIG as u16) & 0xff) as u8);
    pkt.payload = payload;
    // Payload was rebuilt, so any old fragment metadata must be cleared.
    pkt.final_length = None;
    pkt.flags = (pkt.flags & !FRAME_TYPE_MASK) | FRAME_TYPE_FIRST | FRAME_TYPE_LAST;
    Ok(())
}

fn rewrite_media_ack(pkt: &mut Packet, session_id: i32, ack_counter: u32) -> Result<()> {
    let mut ack = Ack::new();
    ack.set_session_id(session_id);
    ack.set_ack(ack_counter);

    let mut payload = ack.write_to_bytes()?;
    payload.insert(0, ((MEDIA_MESSAGE_ACK as u16) >> 8) as u8);
    payload.insert(1, ((MEDIA_MESSAGE_ACK as u16) & 0xff) as u8);
    pkt.payload = payload;
    // Payload was rebuilt, so any old fragment metadata must be cleared.
    pkt.final_length = None;
    pkt.flags = (pkt.flags & !FRAME_TYPE_MASK) | FRAME_TYPE_FIRST | FRAME_TYPE_LAST;
    Ok(())
}

fn rewrite_video_focus_notification(
    pkt: &mut Packet,
    focus: VideoFocusMode,
    unsolicited: bool,
) -> Result<()> {
    let mut notification = VideoFocusNotification::new();
    notification.set_focus(focus);
    notification.set_unsolicited(unsolicited);

    let mut payload = notification.write_to_bytes()?;
    payload.insert(
        0,
        ((MEDIA_MESSAGE_VIDEO_FOCUS_NOTIFICATION as u16) >> 8) as u8,
    );
    payload.insert(
        1,
        ((MEDIA_MESSAGE_VIDEO_FOCUS_NOTIFICATION as u16) & 0xff) as u8,
    );
    pkt.payload = payload;
    // Payload was rebuilt, so any old fragment metadata must be cleared.
    pkt.final_length = None;
    pkt.flags = (pkt.flags & !FRAME_TYPE_MASK) | FRAME_TYPE_FIRST | FRAME_TYPE_LAST;
    Ok(())
}

pub fn maybe_emit_pending_injected_focus(
    proxy_type: ProxyType,
    ctx: &mut ModifyContext,
    cfg: &AppConfig,
    tx: &Sender<Packet>,
) -> Result<()> {
    let mut ready_channels: Vec<(u8, u8, bool)> = Vec::new();
    let mut toggle_channels: Vec<(u8, u8)> = Vec::new();
    let mut release_channels: Vec<(u8, u8)> = Vec::new();
    let mut connect_gen_updates: Vec<(u8, u64)> = Vec::new();
    let mut tap_presence_updates: Vec<(u8, bool)> = Vec::new();

    for (&channel, state) in &ctx.injected_media_state {
        let sink = ctx.media_channels.get(&channel);
        let has_tap_client = sink.map(|s| s.has_subscribers()).unwrap_or(false);
        let connect_gen = sink
            .map(|s| s.client_connect_generation())
            .unwrap_or_default();
        let seen_connect_gen = ctx
            .injected_media_connect_gen
            .get(&channel)
            .copied()
            .unwrap_or_default();
        let new_connection = connect_gen > seen_connect_gen;
        let had_tap_client = ctx
            .injected_media_had_tap_client
            .get(&channel)
            .copied()
            .unwrap_or(false);
        let lost_last_consumer = had_tap_client && !has_tap_client;

        connect_gen_updates.push((channel, connect_gen));
        tap_presence_updates.push((channel, has_tap_client));

        let is_cluster = ctx
            .injected_media_display
            .get(&channel)
            .copied()
            .unwrap_or(DisplayType::DISPLAY_TYPE_CLUSTER)
            == DisplayType::DISPLAY_TYPE_CLUSTER;

        if new_connection
            && has_tap_client
            && is_cluster
            && matches!(
                state.phase,
                InjectedMediaPhase::FocusSent
                    | InjectedMediaPhase::Started
                    | InjectedMediaPhase::Streaming
            )
        {
            toggle_channels.push((channel, state.last_flags));
        }

        // Reconnect into Idle: re-acquire projected focus so the phone restarts the stream.
        if new_connection && has_tap_client && is_cluster && state.phase == InjectedMediaPhase::Idle
        {
            info!(
                "{} <blue>injected media:</> new tap client on channel {:#04x} in idle phase; re-acquiring projected focus",
                get_name(proxy_type),
                channel
            );
            ready_channels.push((channel, state.last_flags, has_tap_client));
        }

        if lost_last_consumer
            && is_cluster
            && !cfg.inject_force_focus_without_tap
            && matches!(
                state.phase,
                InjectedMediaPhase::FocusSent
                    | InjectedMediaPhase::Started
                    | InjectedMediaPhase::Streaming
            )
        {
            release_channels.push((channel, state.last_flags));
        }

        if !state.phase.awaiting_focus() {
            continue;
        }

        debug!(
            "{} deferred_focus check: ch={:#04x} tap_client={} force={} media_channels_has_sink={} connect_gen={} seen_connect_gen={} new_connection={}",
            get_name(proxy_type),
            channel,
            has_tap_client,
            cfg.inject_force_focus_without_tap,
            ctx.media_channels.contains_key(&channel),
            connect_gen,
            seen_connect_gen,
            new_connection
        );

        if has_tap_client || cfg.inject_force_focus_without_tap {
            ready_channels.push((channel, state.last_flags, has_tap_client));
        }
    }

    // Reacquire projected focus on fresh cluster tap connections even if we do not
    // currently have injected media runtime state for that channel.
    for (&channel, &display_type) in &ctx.injected_media_display {
        if display_type != DisplayType::DISPLAY_TYPE_CLUSTER {
            continue;
        }
        if ctx.injected_media_state.contains_key(&channel) {
            continue;
        }

        let Some(sink) = ctx.media_channels.get(&channel) else {
            continue;
        };

        let has_tap_client = sink.has_subscribers();
        let connect_gen = sink.client_connect_generation();
        let seen_connect_gen = ctx
            .injected_media_connect_gen
            .get(&channel)
            .copied()
            .unwrap_or_default();
        let new_connection = connect_gen > seen_connect_gen;

        connect_gen_updates.push((channel, connect_gen));
        tap_presence_updates.push((channel, has_tap_client));

        if new_connection && has_tap_client {
            debug!(
                "{} deferred_focus check: ch={:#04x} phase=absent tap_client=true force={} media_channels_has_sink=true connect_gen={} seen_connect_gen={} new_connection=true",
                get_name(proxy_type),
                channel,
                cfg.inject_force_focus_without_tap,
                connect_gen,
                seen_connect_gen,
            );
            toggle_channels.push((channel, ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST));
        }
    }

    for (channel, connect_gen) in connect_gen_updates {
        ctx.injected_media_connect_gen.insert(channel, connect_gen);
    }

    for (channel, has_tap_client) in tap_presence_updates {
        ctx.injected_media_had_tap_client
            .insert(channel, has_tap_client);
    }

    for (channel, flags) in release_channels {
        let mut release_focus_pkt = Packet {
            channel,
            flags,
            final_length: None,
            payload: Vec::new(),
        };
        rewrite_video_focus_notification(
            &mut release_focus_pkt,
            VideoFocusMode::VIDEO_FOCUS_NATIVE,
            true,
        )?;

        info!(
            "{} <blue>injected media:</> last tap client disconnected on channel <b>{:#04x}</>; releasing projected focus",
            get_name(proxy_type),
            channel
        );

        match tx.try_send(release_focus_pkt) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    "{} <yellow>cluster focus release backpressure:</> queue full while sending native focus for channel <b>{:#04x}</>; will retry",
                    get_name(proxy_type),
                    channel
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err("injected focus queue closed".into());
            }
        }
    }

    for (channel, flags) in toggle_channels {
        let mut drop_focus_pkt = Packet {
            channel,
            flags,
            final_length: None,
            payload: Vec::new(),
        };
        rewrite_video_focus_notification(
            &mut drop_focus_pkt,
            VideoFocusMode::VIDEO_FOCUS_NATIVE,
            true,
        )?;

        let mut project_focus_pkt = Packet {
            channel,
            flags,
            final_length: None,
            payload: Vec::new(),
        };
        rewrite_video_focus_notification(
            &mut project_focus_pkt,
            VideoFocusMode::VIDEO_FOCUS_PROJECTED,
            true,
        )?;

        info!(
            "{} <blue>injected media:</> cluster tap client connected on channel <b>{:#04x}</>; toggling VIDEO_FOCUS_NOTIFICATION native→projected",
            get_name(proxy_type),
            channel
        );

        let mut drop_sent = false;
        match tx.try_send(drop_focus_pkt) {
            Ok(()) => {
                drop_sent = true;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    "{} <yellow>cluster focus toggle backpressure:</> queue full while sending native focus for channel <b>{:#04x}</>; will retry",
                    get_name(proxy_type),
                    channel
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err("injected focus queue closed".into());
            }
        }

        match tx.try_send(project_focus_pkt) {
            Ok(()) => {
                debug!(
                    "{} cluster focus toggle on channel <b>{:#04x}</>: native_sent={} projected_sent=true",
                    get_name(proxy_type),
                    channel,
                    drop_sent
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    "{} <yellow>cluster focus toggle backpressure:</> queue full while sending projected focus for channel <b>{:#04x}</>; will retry",
                    get_name(proxy_type),
                    channel
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err("injected focus queue closed".into());
            }
        }
    }

    for (channel, flags, has_tap_client) in ready_channels {
        let mut focus_pkt = Packet {
            channel,
            flags,
            final_length: None,
            payload: Vec::new(),
        };
        rewrite_video_focus_notification(
            &mut focus_pkt,
            VideoFocusMode::VIDEO_FOCUS_PROJECTED,
            true,
        )?;
        info!(
            "{} <blue>injected media:</> synthesized VIDEO_FOCUS_NOTIFICATION on channel <b>{:#04x}</> tap_client={} force={}",
            get_name(proxy_type),
            channel,
            has_tap_client,
            cfg.inject_force_focus_without_tap
        );

        match tx.try_send(focus_pkt) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    "{} <yellow>deferred focus backpressure:</> queue full while emitting focus for channel <b>{:#04x}</>; will retry",
                    get_name(proxy_type),
                    channel
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err("injected focus queue closed".into());
            }
        }
    }

    Ok(())
}

pub fn emulate_injected_media_packet(
    proxy_type: ProxyType,
    pkt: &mut Packet,
    ctx: &mut ModifyContext,
    reassembled_frame: Option<&[u8]>,
    has_fragment_state: bool,
) -> Result<bool> {
    let message_id = first_fragment_message_id(pkt)
        .or_else(|| {
            reassembled_frame.and_then(|frame| {
                if frame.len() >= 2 {
                    Some(u16::from_be_bytes([frame[0], frame[1]]))
                } else {
                    None
                }
            })
        })
        .or_else(|| {
            if has_fragment_state {
                Some(MEDIA_MESSAGE_DATA.value() as u16)
            } else {
                None
            }
        });

    let Some(message_id) = message_id else {
        return Ok(false);
    };

    let data = reassembled_frame
        .and_then(|frame| frame.get(2..))
        .or_else(|| pkt.payload.get(2..))
        .unwrap_or_default();
    let state = ctx.injected_media_state.entry(pkt.channel).or_default();
    let display_type = ctx
        .injected_media_display
        .get(&pkt.channel)
        .copied()
        .unwrap_or(DisplayType::DISPLAY_TYPE_CLUSTER);
    let max_unacked = injected_max_unacked(display_type);

    match MediaMessageId::from_i32(message_id.into()).unwrap_or(MEDIA_MESSAGE_DATA) {
        MEDIA_MESSAGE_SETUP => {
            state.phase = InjectedMediaPhase::SetupSeen;
            state.session_id = 0;
            state.ack_counter = 0;
            state.last_flags = pkt.flags;
            info!(
                "{} <blue>injected media:</> SETUP on channel <b>{:#04x}</> display={:?}",
                get_name(proxy_type),
                pkt.channel,
                display_type
            );
            // Virtual sink: immediately advertise readiness and keep unacked window tiny.
            rewrite_media_config_ready(pkt, max_unacked)?;
            Ok(true)
        }
        MEDIA_MESSAGE_START => {
            if let Ok(msg) = Start::parse_from_bytes(data) {
                state.session_id = msg.session_id();
                state.ack_counter = 0;
                state.phase = InjectedMediaPhase::Started;
                state.last_flags = pkt.flags;
                state.trace_after_start = 128;
                info!(
                    "{} <blue>injected media:</> START on channel <b>{:#04x}</> display={:?} session_id={} cfg_index={}",
                    get_name(proxy_type),
                    pkt.channel,
                    display_type,
                    msg.session_id(),
                    msg.configuration_index()
                );
            } else {
                warn!(
                    "{} <yellow>injected media:</> START parse failed on channel <b>{:#04x}</> display={:?}",
                    get_name(proxy_type),
                    pkt.channel,
                    display_type
                );
            }
            // Native sinks do not emit a control reply for START. Emitting CONFIG here
            // can stall phone-side control flow right after injected startup.
            Ok(false)
        }
        MEDIA_MESSAGE_DATA => {
            if reassembled_frame.is_none()
                && (has_fragment_state
                    || pkt.flags & FRAME_TYPE_MASK != (FRAME_TYPE_FIRST | FRAME_TYPE_LAST))
            {
                debug!(
                    "{} <blue>injected media:</> fragment_wait on channel <b>{:#04x}</> display={:?}",
                    get_name(proxy_type),
                    pkt.channel,
                    display_type
                );
                return Ok(false);
            }

            if state.phase.can_stream() {
                state.phase = InjectedMediaPhase::Streaming;
                state.ack_counter = state.ack_counter.saturating_add(1);
                rewrite_media_ack(pkt, state.session_id, state.ack_counter)?;
                if state.ack_counter == 1 || state.ack_counter % 256 == 0 {
                    info!(
                        "{} <blue>injected media:</> DATA ack on channel <b>{:#04x}</> display={:?} session_id={} ack={}",
                        get_name(proxy_type),
                        pkt.channel,
                        display_type,
                        state.session_id,
                        state.ack_counter
                    );
                }
                return Ok(true);
            }

            warn!(
                "{} <yellow>injected media:</> state_not_started on channel <b>{:#04x}</> display={:?}",
                get_name(proxy_type),
                pkt.channel,
                display_type
            );
            Ok(false)
        }
        MEDIA_MESSAGE_STOP => {
            info!(
                "{} <blue>injected media:</> STOP on channel <b>{:#04x}</> display={:?} session_id={} final_ack={}",
                get_name(proxy_type),
                pkt.channel,
                display_type,
                state.session_id,
                state.ack_counter
            );
            state.phase = InjectedMediaPhase::Idle;
            state.ack_counter = 0;
            state.session_id = 0;
            state.last_flags = pkt.flags;
            Ok(false)
        }
        MEDIA_MESSAGE_VIDEO_FOCUS_REQUEST => {
            let mut requested_focus = VideoFocusMode::VIDEO_FOCUS_PROJECTED;
            let mut reason = VideoFocusReason::UNKNOWN;
            if let Ok(msg) = VideoFocusRequestNotification::parse_from_bytes(data) {
                requested_focus = msg.mode();
                reason = msg.reason();
            } else {
                warn!(
                    "{} <yellow>injected media:</> VIDEO_FOCUS_REQUEST parse failed on channel <b>{:#04x}</> display={:?}",
                    get_name(proxy_type),
                    pkt.channel,
                    display_type
                );
            }

            info!(
                "{} <blue>injected media:</> VIDEO_FOCUS_REQUEST on channel <b>{:#04x}</> display={:?} focus={:?} reason={:?}",
                get_name(proxy_type),
                pkt.channel,
                display_type,
                requested_focus,
                reason
            );

            rewrite_video_focus_notification(pkt, requested_focus, false)?;
            state.phase = InjectedMediaPhase::FocusSent;
            Ok(true)
        }
        _ => {
            info!(
                "{} <blue>injected media:</> passthrough message_id=0x{:04X} on channel <b>{:#04x}</> display={:?}",
                get_name(proxy_type),
                message_id,
                pkt.channel,
                display_type
            );
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hu_input::HuInputState;
    use crate::media_tap::reassemble_media_packet;
    use std::collections::{HashMap, HashSet};
    use tokio::sync::mpsc;

    fn make_video_service(id: i32, display_type: DisplayType, display_id: u32) -> Service {
        let mut svc = Service::new();
        svc.set_id(id);

        let mut media = MediaSinkService::new();
        media.set_available_type(MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP);
        media.set_display_type(display_type);
        media.set_display_id(display_id);

        let mut video_cfg = VideoConfiguration::new();
        video_cfg.set_codec_resolution(VideoCodecResolutionType::VIDEO_1280x720);
        video_cfg.set_frame_rate(VideoFrameRateType::VIDEO_FPS_30);
        media.video_configs.push(video_cfg);

        svc.media_sink_service = Some(media).into();
        svc
    }

    fn make_input_service(id: i32, display_id: u32) -> Service {
        let mut svc = Service::new();
        svc.set_id(id);

        let mut input = InputSourceService::new();
        input.set_display_id(display_id);
        svc.input_source_service = Some(input).into();
        svc
    }

    fn test_ctx() -> ModifyContext {
        let (ev_tx, _) = mpsc::channel(1);
        ModifyContext {
            sensor_channel: None,
            sensors: None,
            nav_channel: None,
            audio_channels: vec![],
            ev_tx,
            input_channel: None,
            hu_tx: None,
            hu_input_state: HuInputState::default(),
            media_sinks: HashMap::new(),
            media_channels: HashMap::new(),
            media_fragments: HashMap::new(),
            hu_service_ids: HashSet::new(),
            injected_service_ids: HashSet::new(),
            injected_channels: HashSet::new(),
            injected_media_display: HashMap::new(),
            injected_media_state: HashMap::new(),
            injected_media_connect_gen: HashMap::new(),
            injected_media_had_tap_client: HashMap::new(),
            vendor_service_ids: HashSet::new(),
            vendor_channel_states: HashMap::new(),
            vendor_topic_event_bridges: HashMap::new(),
        }
    }

    fn test_packet(channel: u8, flags: u8, final_length: Option<u32>, payload: &[u8]) -> Packet {
        Packet {
            channel,
            flags,
            final_length,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn media_tap_keeps_single_frame_packets_intact() {
        let mut ctx = test_ctx();
        let pkt = test_packet(
            0x21,
            FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            None,
            &[0x00, 0x01, 0xAA, 0xBB],
        );

        let assembled = reassemble_media_packet(&mut ctx.media_fragments, &pkt);

        assert_eq!(assembled, Some(vec![0x00, 0x01, 0xAA, 0xBB]));
        assert!(!ctx.media_fragments.contains_key(&0x21));
    }

    #[test]
    fn media_tap_reassembles_fragmented_packets() {
        let mut ctx = test_ctx();
        let first = test_packet(0x21, FRAME_TYPE_FIRST, Some(6), &[0x00, 0x01, 0xAA]);
        let middle = test_packet(0x21, 0, None, &[0xBB]);
        let last = test_packet(0x21, FRAME_TYPE_LAST, None, &[0xCC, 0xDD]);

        assert_eq!(
            reassemble_media_packet(&mut ctx.media_fragments, &first),
            None
        );
        assert_eq!(
            reassemble_media_packet(&mut ctx.media_fragments, &middle),
            None
        );
        assert_eq!(
            reassemble_media_packet(&mut ctx.media_fragments, &last),
            Some(vec![0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD])
        );
        assert!(!ctx.media_fragments.contains_key(&0x21));
    }

    #[test]
    fn media_tap_drops_length_mismatches() {
        let mut ctx = test_ctx();
        let first = test_packet(0x21, FRAME_TYPE_FIRST, Some(7), &[0x00, 0x01, 0xAA]);
        let last = test_packet(0x21, FRAME_TYPE_LAST, None, &[0xBB, 0xCC]);

        assert_eq!(
            reassemble_media_packet(&mut ctx.media_fragments, &first),
            None
        );
        assert_eq!(
            reassemble_media_packet(&mut ctx.media_fragments, &last),
            None
        );
        assert!(!ctx.media_fragments.contains_key(&0x21));
    }

    #[test]
    fn add_display_services_adds_cluster_media_and_input_when_opted_in() {
        let mut cfg = AppConfig::default();
        cfg.mitm = true;
        cfg.inject_display_types =
            crate::config_types::InjectDisplayTypes(Some(vec![DisplayType::DISPLAY_TYPE_CLUSTER]));
        cfg.inject_add_input_sources = true;

        let mut msg = ServiceDiscoveryResponse::new();
        msg.services
            .push(make_video_service(1, DisplayType::DISPLAY_TYPE_MAIN, 0));

        let added = add_display_services(&mut msg, &cfg);

        assert_eq!(added, 2);
        assert!(has_video_display(&msg, DisplayType::DISPLAY_TYPE_CLUSTER));
        assert!(has_input_display(
            &msg,
            cfg.inject_cluster_display_id.into()
        ));
    }

    #[test]
    fn auxiliary_input_service_keeps_touchscreen() {
        let mut cfg = AppConfig::default();
        cfg.mitm = true;
        cfg.inject_display_types = crate::config_types::InjectDisplayTypes(Some(vec![
            DisplayType::DISPLAY_TYPE_AUXILIARY,
        ]));
        cfg.inject_add_input_sources = true;

        let mut msg = ServiceDiscoveryResponse::new();
        msg.services
            .push(make_video_service(1, DisplayType::DISPLAY_TYPE_MAIN, 0));

        let added = add_display_services(&mut msg, &cfg);

        assert_eq!(added, 2);
        let aux_input = msg
            .services
            .iter()
            .find(|svc| {
                svc.input_source_service.display_id() == u32::from(cfg.inject_aux_display_id)
            })
            .unwrap();
        assert_eq!(aux_input.input_source_service.touchscreen.len(), 1);
        assert!(aux_input.input_source_service.touchscreen[0].is_secondary());
    }

    #[test]
    fn add_display_services_does_not_duplicate_existing_cluster() {
        let mut cfg = AppConfig::default();
        cfg.mitm = true;
        cfg.inject_display_types =
            crate::config_types::InjectDisplayTypes(Some(vec![DisplayType::DISPLAY_TYPE_CLUSTER]));
        cfg.inject_add_input_sources = true;

        let mut msg = ServiceDiscoveryResponse::new();
        msg.services
            .push(make_video_service(1, DisplayType::DISPLAY_TYPE_MAIN, 0));
        msg.services
            .push(make_video_service(2, DisplayType::DISPLAY_TYPE_CLUSTER, 1));
        msg.services.push(make_input_service(3, 1));

        let added = add_display_services(&mut msg, &cfg);

        assert_eq!(added, 0);
        let cluster_count = msg
            .services
            .iter()
            .filter(|svc| {
                !svc.media_sink_service.video_configs.is_empty()
                    && svc.media_sink_service.display_type() == DisplayType::DISPLAY_TYPE_CLUSTER
            })
            .count();
        assert_eq!(cluster_count, 1);
    }

    #[test]
    fn add_display_services_adds_cluster_without_input_when_not_opted_in() {
        let mut cfg = AppConfig::default();
        cfg.mitm = true;
        cfg.inject_display_types =
            crate::config_types::InjectDisplayTypes(Some(vec![DisplayType::DISPLAY_TYPE_CLUSTER]));
        cfg.inject_add_input_sources = false;

        let mut msg = ServiceDiscoveryResponse::new();
        msg.services
            .push(make_video_service(1, DisplayType::DISPLAY_TYPE_MAIN, 0));

        let added = add_display_services(&mut msg, &cfg);

        assert_eq!(added, 1);
        assert!(has_video_display(&msg, DisplayType::DISPLAY_TYPE_CLUSTER));
        assert!(!has_input_display(
            &msg,
            cfg.inject_cluster_display_id.into()
        ));
    }

    #[test]
    fn injected_media_setup_is_rewritten_to_config_ready() {
        let mut ctx = test_ctx();
        ctx.injected_channels.insert(0x2A);

        let mut setup = Setup::new();
        setup.set_type(MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP);
        let mut payload = setup.write_to_bytes().unwrap();
        payload.insert(0, ((MEDIA_MESSAGE_SETUP as u16) >> 8) as u8);
        payload.insert(1, ((MEDIA_MESSAGE_SETUP as u16) & 0xff) as u8);
        let mut pkt = test_packet(
            0x2A,
            ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            None,
            &payload,
        );

        assert!(emulate_injected_media_packet(
            ProxyType::HeadUnit,
            &mut pkt,
            &mut ctx,
            None,
            false,
        )
        .unwrap());

        let msg_id = u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]) as i32;
        assert_eq!(msg_id, MEDIA_MESSAGE_CONFIG.value());
        assert_eq!(pkt.final_length, None);
        assert_eq!(
            pkt.flags & FRAME_TYPE_MASK,
            FRAME_TYPE_FIRST | FRAME_TYPE_LAST
        );
        let cfg = ProtoConfig::parse_from_bytes(&pkt.payload[2..]).unwrap();
        assert_eq!(cfg.status(), Status::STATUS_READY);
        assert_eq!(cfg.max_unacked(), 1);
    }

    #[test]
    fn injected_media_data_after_start_is_rewritten_to_ack() {
        let mut ctx = test_ctx();
        ctx.injected_channels.insert(0x2A);
        ctx.injected_media_display
            .insert(0x2A, DisplayType::DISPLAY_TYPE_CLUSTER);
        ctx.injected_media_state
            .insert(0x2A, InjectedMediaState::default());

        let mut start = Start::new();
        start.set_session_id(7);
        start.set_configuration_index(0);
        let mut start_payload = start.write_to_bytes().unwrap();
        start_payload.insert(0, ((MEDIA_MESSAGE_START as u16) >> 8) as u8);
        start_payload.insert(1, ((MEDIA_MESSAGE_START as u16) & 0xff) as u8);
        let mut start_pkt = test_packet(
            0x2A,
            ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            None,
            &start_payload,
        );

        assert!(!emulate_injected_media_packet(
            ProxyType::HeadUnit,
            &mut start_pkt,
            &mut ctx,
            None,
            false,
        )
        .unwrap());

        let data_payload = vec![
            ((MEDIA_MESSAGE_DATA as u16) >> 8) as u8,
            ((MEDIA_MESSAGE_DATA as u16) & 0xff) as u8,
            0x00,
            0x01,
        ];
        let mut data_pkt = test_packet(
            0x2A,
            ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            None,
            &data_payload,
        );

        assert!(emulate_injected_media_packet(
            ProxyType::HeadUnit,
            &mut data_pkt,
            &mut ctx,
            Some(&data_payload),
            false,
        )
        .unwrap());

        let msg_id = u16::from_be_bytes([data_pkt.payload[0], data_pkt.payload[1]]) as i32;
        assert_eq!(msg_id, MEDIA_MESSAGE_ACK.value());
        assert_eq!(data_pkt.final_length, None);
        assert_eq!(
            data_pkt.flags & FRAME_TYPE_MASK,
            FRAME_TYPE_FIRST | FRAME_TYPE_LAST
        );
        let ack = Ack::parse_from_bytes(&data_pkt.payload[2..]).unwrap();
        assert_eq!(ack.session_id(), 7);
        assert_eq!(ack.ack(), 1);
    }

    #[test]
    fn fragmented_injected_media_data_waits_for_reassembly_before_ack() {
        let mut ctx = test_ctx();
        ctx.injected_channels.insert(0x2A);
        ctx.injected_media_display
            .insert(0x2A, DisplayType::DISPLAY_TYPE_CLUSTER);

        let mut start = Start::new();
        start.set_session_id(11);
        start.set_configuration_index(0);
        let mut start_payload = start.write_to_bytes().unwrap();
        start_payload.insert(0, ((MEDIA_MESSAGE_START as u16) >> 8) as u8);
        start_payload.insert(1, ((MEDIA_MESSAGE_START as u16) & 0xff) as u8);
        let mut start_pkt = test_packet(
            0x2A,
            ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            None,
            &start_payload,
        );
        assert!(!emulate_injected_media_packet(
            ProxyType::HeadUnit,
            &mut start_pkt,
            &mut ctx,
            None,
            false,
        )
        .unwrap());

        let full_frame = vec![
            ((MEDIA_MESSAGE_DATA as u16) >> 8) as u8,
            ((MEDIA_MESSAGE_DATA as u16) & 0xff) as u8,
            0xAA,
            0xBB,
            0xCC,
            0xDD,
        ];
        let mut first_pkt = test_packet(
            0x2A,
            ENCRYPTED | FRAME_TYPE_FIRST,
            Some(full_frame.len() as u32),
            &full_frame[..4],
        );
        let first_frame = reassemble_media_packet(&mut ctx.media_fragments, &first_pkt);
        assert!(!emulate_injected_media_packet(
            ProxyType::HeadUnit,
            &mut first_pkt,
            &mut ctx,
            first_frame.as_deref(),
            false,
        )
        .unwrap());

        let mut last_pkt = test_packet(0x2A, ENCRYPTED | FRAME_TYPE_LAST, None, &full_frame[4..]);
        let last_frame = reassemble_media_packet(&mut ctx.media_fragments, &last_pkt);
        assert!(emulate_injected_media_packet(
            ProxyType::HeadUnit,
            &mut last_pkt,
            &mut ctx,
            last_frame.as_deref(),
            true,
        )
        .unwrap());

        let msg_id = u16::from_be_bytes([last_pkt.payload[0], last_pkt.payload[1]]) as i32;
        assert_eq!(msg_id, MEDIA_MESSAGE_ACK.value());
        assert_eq!(last_pkt.final_length, None);
        assert_eq!(
            last_pkt.flags & FRAME_TYPE_MASK,
            FRAME_TYPE_FIRST | FRAME_TYPE_LAST
        );
        let ack = Ack::parse_from_bytes(&last_pkt.payload[2..]).unwrap();
        assert_eq!(ack.session_id(), 11);
        assert_eq!(ack.ack(), 1);
    }

    #[test]
    fn deferred_injected_focus_does_not_block_when_queue_is_full() {
        let mut ctx = test_ctx();
        ctx.injected_media_state.insert(
            0x2A,
            InjectedMediaState {
                phase: InjectedMediaPhase::SetupSeen,
                last_flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
                ..Default::default()
            },
        );

        let mut cfg = AppConfig::default();
        cfg.inject_force_focus_without_tap = true;

        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(test_packet(0, 0, None, &[])).unwrap();

        maybe_emit_pending_injected_focus(ProxyType::HeadUnit, &mut ctx, &cfg, &tx).unwrap();

        assert!(ctx
            .injected_media_state
            .get(&0x2A)
            .is_some_and(|state| state.phase == InjectedMediaPhase::SetupSeen));
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn injected_aux_media_setup_uses_aux_profile_unacked_window() {
        let mut ctx = test_ctx();
        ctx.injected_media_display
            .insert(0x2B, DisplayType::DISPLAY_TYPE_AUXILIARY);

        let mut setup = Setup::new();
        setup.set_type(MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP);
        let mut payload = setup.write_to_bytes().unwrap();
        payload.insert(0, ((MEDIA_MESSAGE_SETUP as u16) >> 8) as u8);
        payload.insert(1, ((MEDIA_MESSAGE_SETUP as u16) & 0xff) as u8);
        let mut pkt = test_packet(
            0x2B,
            ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            None,
            &payload,
        );

        assert!(emulate_injected_media_packet(
            ProxyType::HeadUnit,
            &mut pkt,
            &mut ctx,
            None,
            false,
        )
        .unwrap());

        let cfg = ProtoConfig::parse_from_bytes(&pkt.payload[2..]).unwrap();
        assert_eq!(cfg.max_unacked(), 2);
        assert_eq!(cfg.configuration_indices, vec![0]);
    }
}
