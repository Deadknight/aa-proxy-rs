use crate::config::BtScoMediaBridgeResampler;
use simplelog::*;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const NAME: &str = "<i><bright-black> bt-sco: </>";

// Linux Bluetooth constants. Keep them explicit because some cross libc headers do
// not expose all Bluetooth-specific names in Rust.
const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_SCO: libc::c_int = 2;
const SOL_SCO: libc::c_int = 17;
const SOL_BLUETOOTH: libc::c_int = 274;

const SCO_OPTIONS: libc::c_int = 0x01;
const SCO_CONNINFO: libc::c_int = 0x02;
const BT_VOICE: libc::c_int = 11;
const BT_SNDMTU: libc::c_int = 12;
const BT_RCVMTU: libc::c_int = 13;

/// Target size for bridge chunks: about 20ms of 48kHz stereo s16le PCM.
/// The SCO packet cadence produces 60-byte input packets, so actual chunks are
/// usually 22.5ms / 4320 bytes after the 6x stereo expansion.
pub const AA_MEDIA_PCM_TARGET_CHUNK_BYTES: usize = 48_000 * 2 * 2 / 50;
const DEFAULT_AA_PCM_RING_CAPACITY: usize = 128;
pub const SCO_UPLINK_PACKET_BYTES: usize = 60;
const DEFAULT_SCO_UPLINK_RING_CAPACITY: usize = 256;
const SCO_DOWNLINK_AUDIO_LOG_PEAK_THRESHOLD: i16 = 64;

#[derive(Debug, Clone)]
pub struct AaPcmFrame {
    pub generation: u64,
    pub pcm: Vec<u8>,
}

static AA_PCM_RING: OnceLock<Arc<Mutex<VecDeque<AaPcmFrame>>>> = OnceLock::new();
static SCO_UPLINK_RING: OnceLock<Arc<Mutex<VecDeque<Vec<u8>>>>> = OnceLock::new();
static SCO_UPLINK_PENDING: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
static SCO_CONNECTED: AtomicBool = AtomicBool::new(false);
static SCO_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct BtScoOptions {
    /// Convert the confirmed SCO downlink format (8kHz s16le mono) into
    /// AA-friendly media PCM (48kHz s16le stereo) and expose it through the
    /// in-process bridge ring buffer.
    pub bridge_aa_media_pcm: bool,
    /// Maximum number of converted AA PCM chunks held in the bridge ring.
    /// Old chunks are dropped first to keep latency bounded.
    pub bridge_ring_capacity: usize,
    /// SCO 8 kHz -> AA 48 kHz resampler used for downlink conversion.
    /// `Repeat` preserves the original proven behavior; `Linear` smooths the
    /// integer 6x upsampling and can reduce roughness/crackle.
    pub media_resampler: BtScoMediaBridgeResampler,
    /// Write HU microphone PCM frames back to the SCO/eSCO socket as uplink.
    /// When enabled, silence is written if no mic frame is available yet, so the
    /// phone keeps receiving a steady SCO uplink stream.
    pub bridge_sco_uplink_pcm: bool,
    /// Maximum number of 60-byte SCO uplink packets buffered for the microphone bridge.
    pub sco_uplink_ring_capacity: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BdAddr {
    b: [u8; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SockAddrSco {
    sco_family: libc::sa_family_t,
    sco_bdaddr: BdAddr,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct ScoOptions {
    mtu: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct ScoConnInfo {
    hci_handle: u16,
    dev_class: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct BtVoice {
    setting: u16,
}

#[derive(Debug, Default)]
struct ScoStats {
    packets: u64,
    bytes: u64,
    min_packet_len: usize,
    max_packet_len: usize,
    packet_len_histogram: BTreeMap<usize, u64>,
    first_packet_at: Option<Instant>,
    last_packet_at: Option<Instant>,
    min_interarrival_us: Option<u128>,
    max_interarrival_us: Option<u128>,
    interarrival_total_us: u128,
    interarrival_count: u64,
}

impl ScoStats {
    fn observe(&mut self, len: usize, now: Instant) {
        if self.packets == 0 {
            self.min_packet_len = len;
            self.max_packet_len = len;
            self.first_packet_at = Some(now);
        } else {
            self.min_packet_len = self.min_packet_len.min(len);
            self.max_packet_len = self.max_packet_len.max(len);

            if let Some(last) = self.last_packet_at {
                let delta_us = now.duration_since(last).as_micros();
                self.min_interarrival_us = Some(
                    self.min_interarrival_us
                        .map(|v| v.min(delta_us))
                        .unwrap_or(delta_us),
                );
                self.max_interarrival_us = Some(
                    self.max_interarrival_us
                        .map(|v| v.max(delta_us))
                        .unwrap_or(delta_us),
                );
                self.interarrival_total_us += delta_us;
                self.interarrival_count += 1;
            }
        }

        self.last_packet_at = Some(now);
        self.packets += 1;
        self.bytes += len as u64;
        *self.packet_len_histogram.entry(len).or_insert(0) += 1;
    }

    fn elapsed_secs(&self, fallback_started: Instant) -> f64 {
        match (self.first_packet_at, self.last_packet_at) {
            (Some(first), Some(last)) if last > first => last.duration_since(first).as_secs_f64(),
            _ => fallback_started.elapsed().as_secs_f64(),
        }
    }

    fn bytes_per_sec(&self, fallback_started: Instant) -> f64 {
        let elapsed = self.elapsed_secs(fallback_started);
        if elapsed > 0.0 {
            self.bytes as f64 / elapsed
        } else {
            0.0
        }
    }

    fn packets_per_sec(&self, fallback_started: Instant) -> f64 {
        let elapsed = self.elapsed_secs(fallback_started);
        if elapsed > 0.0 {
            self.packets as f64 / elapsed
        } else {
            0.0
        }
    }

    fn inferred_s16le_mono_hz(&self, fallback_started: Instant) -> f64 {
        self.bytes_per_sec(fallback_started) / 2.0
    }

    fn avg_interarrival_ms(&self) -> f64 {
        if self.interarrival_count == 0 {
            0.0
        } else {
            (self.interarrival_total_us as f64 / self.interarrival_count as f64) / 1000.0
        }
    }

    fn top_packet_lengths(&self) -> String {
        let mut items: Vec<(usize, u64)> = self
            .packet_len_histogram
            .iter()
            .map(|(len, count)| (*len, *count))
            .collect();
        items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        items
            .into_iter()
            .take(5)
            .map(|(len, count)| format!("{}B:{}", len, count))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn summary(&self, started: Instant) -> String {
        format!(
            "packets={}, bytes={}, packet_len[min/max/top]={}/{}/[{}], rate={:.1} pkt/s {:.1} B/s inferred_s16le_mono={:.1} Hz, iat_ms[min/avg/max]={:.3}/{:.3}/{:.3}",
            self.packets,
            self.bytes,
            self.min_packet_len,
            self.max_packet_len,
            self.top_packet_lengths(),
            self.packets_per_sec(started),
            self.bytes_per_sec(started),
            self.inferred_s16le_mono_hz(started),
            self.min_interarrival_us.unwrap_or(0) as f64 / 1000.0,
            self.avg_interarrival_ms(),
            self.max_interarrival_us.unwrap_or(0) as f64 / 1000.0,
        )
    }
}

/// Start the SCO/eSCO call-audio listener on a plain blocking thread.
///
/// This does not register any Bluetooth profile and is disabled by default.
/// It accepts the SCO/eSCO socket used by the phone call route and optionally
/// bridges downlink/uplink audio to Android Auto media/microphone channels.
pub fn spawn(options: BtScoOptions) -> io::Result<thread::JoinHandle<()>> {
    if options.bridge_aa_media_pcm {
        enable_aa_pcm_ring();
    }
    if options.bridge_sco_uplink_pcm {
        enable_sco_uplink_ring();
    }

    thread::Builder::new()
        .name("bt-sco".to_string())
        .spawn(move || {
            if let Err(e) = run(options) {
                error!("{} stopped: {}", NAME, e);
            }
        })
}

fn run(options: BtScoOptions) -> io::Result<()> {
    let listener = create_sco_listener()?;

    info!(
        "{} listening for incoming SCO/eSCO audio, bridge_aa_media_pcm={}, media_ring_capacity={}, bridge_sco_uplink_pcm={}, uplink_ring_capacity={}",
        NAME,
        options.bridge_aa_media_pcm,
        effective_ring_capacity(options.bridge_ring_capacity),
        options.bridge_sco_uplink_pcm,
        effective_sco_uplink_capacity(options.sco_uplink_ring_capacity)
    );

    loop {
        let mut peer: SockAddrSco = unsafe { mem::zeroed() };
        let mut peer_len = mem::size_of::<SockAddrSco>() as libc::socklen_t;

        let fd = unsafe {
            libc::accept(
                listener,
                &mut peer as *mut SockAddrSco as *mut libc::sockaddr,
                &mut peer_len as *mut libc::socklen_t,
            )
        };

        if fd < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }

            warn!("{} SCO accept error: {}", NAME, e);
            thread::sleep(Duration::from_millis(200));
            continue;
        }

        let generation = SCO_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        clear_aa_pcm_queue();
        SCO_CONNECTED.store(true, Ordering::SeqCst);
        clear_sco_uplink_queue();

        info!(
            "{} SCO/eSCO connected from {}, generation={}",
            NAME,
            format_bdaddr(peer.sco_bdaddr),
            generation
        );
        log_sco_socket_info(fd);

        handle_sco_connection(fd, &options, generation);

        SCO_CONNECTED.store(false, Ordering::SeqCst);
        clear_aa_pcm_queue();
        clear_sco_uplink_queue();
    }
}

fn create_sco_listener() -> io::Result<RawFd> {
    let fd = unsafe { libc::socket(AF_BLUETOOTH, libc::SOCK_SEQPACKET, BTPROTO_SCO) };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let addr = SockAddrSco {
        sco_family: AF_BLUETOOTH as libc::sa_family_t,
        sco_bdaddr: BdAddr { b: [0; 6] }, // BDADDR_ANY
    };

    let bind_result = unsafe {
        libc::bind(
            fd,
            &addr as *const SockAddrSco as *const libc::sockaddr,
            mem::size_of::<SockAddrSco>() as libc::socklen_t,
        )
    };

    if bind_result < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

    let listen_result = unsafe { libc::listen(fd, 1) };

    if listen_result < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

    Ok(fd)
}

fn handle_sco_connection(fd: RawFd, options: &BtScoOptions, generation: u64) {
    let started = Instant::now();

    let mut buf = [0u8; 2048];
    let mut stats = ScoStats::default();
    let mut last_log = Instant::now();
    let mut aa_pcm_chunk: Vec<u8> = Vec::with_capacity(AA_MEDIA_PCM_TARGET_CHUNK_BYTES * 2);
    let mut downlink_resampler_state = DownlinkResamplerState::default();
    let mut audio_window_peak = 0i16;
    let mut audio_window_energy = 0u128;
    let mut audio_window_samples = 0u64;
    let mut audio_window_silent_packets = 0u64;
    let mut audio_window_non_silent_packets = 0u64;
    let mut first_non_silent_at: Option<Instant> = None;
    let mut first_non_silent_packet = 0u64;

    loop {
        let n = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
            )
        };
        let now = Instant::now();

        if n < 0 {
            let e = io::Error::last_os_error();
            warn!("{} SCO read error: {}", NAME, e);
            break;
        }

        if n == 0 {
            info!("{} SCO EOF", NAME);
            break;
        }

        let n = n as usize;
        stats.observe(n, now);
        let (packet_peak, packet_energy, packet_samples, packet_rms) = audio_metrics_s16le(&buf[..n]);
        audio_window_peak = audio_window_peak.max(packet_peak);
        audio_window_energy = audio_window_energy.saturating_add(packet_energy);
        audio_window_samples = audio_window_samples.saturating_add(packet_samples);
        if packet_peak >= SCO_DOWNLINK_AUDIO_LOG_PEAK_THRESHOLD {
            audio_window_non_silent_packets += 1;
            if first_non_silent_at.is_none() {
                first_non_silent_at = Some(now);
                first_non_silent_packet = stats.packets;
                info!(
                    "{} first non-silent SCO downlink packet: packet={}, after={}ms, peak={}, rms={:.1}, threshold={}",
                    NAME,
                    first_non_silent_packet,
                    now.duration_since(started).as_millis(),
                    packet_peak,
                    packet_rms,
                    SCO_DOWNLINK_AUDIO_LOG_PEAK_THRESHOLD
                );
            }
        } else {
            audio_window_silent_packets += 1;
        }

        if stats.packets <= 10 {
            debug!(
                "{} SCO packet #{} len={} hex={}",
                NAME,
                stats.packets,
                n,
                hex::encode(&buf[..n.min(64)])
            );
        }

        if options.bridge_aa_media_pcm {
            sco_s16le_mono_8k_to_aa_pcm_s16le_stereo_48k(
                &buf[..n],
                &mut aa_pcm_chunk,
                options.media_resampler,
                &mut downlink_resampler_state,
            );
            if aa_pcm_chunk.len() >= AA_MEDIA_PCM_TARGET_CHUNK_BYTES {
                push_aa_pcm_frame(
                    std::mem::take(&mut aa_pcm_chunk),
                    options.bridge_ring_capacity,
                    generation,
                );
            }
        }

        if options.bridge_sco_uplink_pcm {
            let uplink = pop_sco_uplink_frame(n).unwrap_or_else(|| vec![0u8; n]);
            let written = unsafe {
                libc::write(
                    fd,
                    uplink.as_ptr() as *const libc::c_void,
                    uplink.len() as libc::size_t,
                )
            };

            if written < 0 {
                warn!(
                    "{} SCO mic-uplink write error: {}",
                    NAME,
                    io::Error::last_os_error()
                );
            }
        }

        if last_log.elapsed() >= Duration::from_secs(5) {
            let window_rms = rms_from_energy(audio_window_energy, audio_window_samples);
            let first_audio_ms = first_non_silent_at
                .map(|t| t.duration_since(started).as_millis().to_string())
                .unwrap_or_else(|| "none".to_string());
            info!(
                "{} SCO active: {}, audio_window[peak={}, rms={:.1}, non_silent_packets={}, silent_packets={}, first_audio_ms={}, first_audio_packet={}], elapsed={}s",
                NAME,
                stats.summary(started),
                audio_window_peak,
                window_rms,
                audio_window_non_silent_packets,
                audio_window_silent_packets,
                first_audio_ms,
                first_non_silent_packet,
                started.elapsed().as_secs()
            );
            audio_window_peak = 0;
            audio_window_energy = 0;
            audio_window_samples = 0;
            audio_window_silent_packets = 0;
            audio_window_non_silent_packets = 0;
            last_log = Instant::now();
        }
    }

    if options.bridge_aa_media_pcm && !aa_pcm_chunk.is_empty() {
        debug!(
            "{} dropping trailing partial AA PCM chunk on SCO disconnect: generation={}, bytes={}",
            NAME,
            generation,
            aa_pcm_chunk.len()
        );
    }

    unsafe {
        libc::close(fd);
    }

    info!(
        "{} SCO disconnected: {}, elapsed={}s",
        NAME,
        stats.summary(started),
        started.elapsed().as_secs()
    );
}

fn enable_aa_pcm_ring() -> Arc<Mutex<VecDeque<AaPcmFrame>>> {
    AA_PCM_RING
        .get_or_init(|| Arc::new(Mutex::new(VecDeque::new())))
        .clone()
}

fn effective_ring_capacity(capacity: usize) -> usize {
    if capacity == 0 {
        DEFAULT_AA_PCM_RING_CAPACITY
    } else {
        capacity
    }
}

fn push_aa_pcm_frame(frame: Vec<u8>, capacity: usize, generation: u64) {
    if frame.is_empty() || generation == 0 {
        return;
    }

    let ring = enable_aa_pcm_ring();
    let mut q = ring.lock().unwrap();
    let capacity = effective_ring_capacity(capacity);
    while q.len() >= capacity {
        q.pop_front();
    }
    q.push_back(AaPcmFrame { generation, pcm: frame });
}

pub fn pop_aa_pcm_frame() -> Option<AaPcmFrame> {
    let ring = AA_PCM_RING.get()?;
    ring.lock().unwrap().pop_front()
}

pub fn pop_aa_pcm_frame_for_generation(generation: u64) -> Option<AaPcmFrame> {
    let ring = AA_PCM_RING.get()?;
    let mut q = ring.lock().unwrap();

    while let Some(frame) = q.pop_front() {
        if frame.generation == generation {
            return Some(frame);
        }
        debug!(
            "{} discarding stale AA PCM frame: frame_generation={}, active_generation={}, bytes={}",
            NAME,
            frame.generation,
            generation,
            frame.pcm.len()
        );
    }

    None
}

pub fn aa_pcm_frame_count() -> usize {
    AA_PCM_RING
        .get()
        .map(|ring| ring.lock().unwrap().len())
        .unwrap_or(0)
}

pub fn aa_pcm_frame_count_for_generation(generation: u64) -> usize {
    AA_PCM_RING
        .get()
        .map(|ring| {
            ring.lock()
                .unwrap()
                .iter()
                .filter(|frame| frame.generation == generation)
                .count()
        })
        .unwrap_or(0)
}

pub fn clear_aa_pcm_queue() {
    if let Some(ring) = AA_PCM_RING.get() {
        ring.lock().unwrap().clear();
    }
}

fn enable_sco_uplink_ring() -> Arc<Mutex<VecDeque<Vec<u8>>>> {
    SCO_UPLINK_RING
        .get_or_init(|| Arc::new(Mutex::new(VecDeque::new())))
        .clone()
}

fn enable_sco_uplink_pending() -> Arc<Mutex<Vec<u8>>> {
    SCO_UPLINK_PENDING
        .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
        .clone()
}

fn effective_sco_uplink_capacity(capacity: usize) -> usize {
    if capacity == 0 {
        DEFAULT_SCO_UPLINK_RING_CAPACITY
    } else {
        capacity
    }
}

pub fn is_sco_connected() -> bool {
    SCO_CONNECTED.load(Ordering::SeqCst)
}

pub fn sco_generation() -> u64 {
    SCO_GENERATION.load(Ordering::SeqCst)
}

pub fn clear_sco_uplink_queue() {
    if let Some(ring) = SCO_UPLINK_RING.get() {
        ring.lock().unwrap().clear();
    }
    if let Some(pending) = SCO_UPLINK_PENDING.get() {
        pending.lock().unwrap().clear();
    }
}

fn push_sco_uplink_packet(packet: Vec<u8>, capacity: usize) {
    if packet.is_empty() {
        return;
    }

    let ring = enable_sco_uplink_ring();
    let mut q = ring.lock().unwrap();
    let capacity = effective_sco_uplink_capacity(capacity);
    while q.len() >= capacity {
        q.pop_front();
    }
    q.push_back(packet);
}

fn pop_sco_uplink_frame(len: usize) -> Option<Vec<u8>> {
    let ring = SCO_UPLINK_RING.get()?;
    let mut q = ring.lock().unwrap();
    let mut frame = q.pop_front()?;

    if frame.len() == len {
        Some(frame)
    } else if frame.len() > len {
        let rest = frame.split_off(len);
        q.push_front(rest);
        Some(frame)
    } else {
        frame.resize(len, 0);
        Some(frame)
    }
}

/// Convert Android Auto microphone/source PCM to the SCO uplink format observed on
/// the target setup: signed 16-bit little-endian, mono, 8 kHz, 60-byte packets.
///
/// Current HUs usually expose the mic source as 16 kHz mono PCM, so the common
/// path simply keeps every second sample. For 48 kHz sources it keeps every sixth
/// sample. If the source is already 8 kHz, it passes samples through.
pub fn push_sco_uplink_pcm_from_aa_mic(
    input: &[u8],
    sample_rate: u32,
    channels: u32,
    bits: u32,
    capacity: usize,
) {
    if input.is_empty() {
        return;
    }

    if bits != 16 || channels == 0 || sample_rate == 0 {
        warn!(
            "{} unsupported AA mic format for SCO uplink: {}Hz, {}ch, {}bit, dropping {} bytes",
            NAME,
            sample_rate,
            channels,
            bits,
            input.len()
        );
        return;
    }

    let frame_bytes = channels as usize * 2;
    if frame_bytes == 0 || input.len() < frame_bytes {
        return;
    }

    let step = if sample_rate >= SCO_LINEAR_PCM_SAMPLE_RATE_HZ {
        (sample_rate / SCO_LINEAR_PCM_SAMPLE_RATE_HZ).max(1) as usize
    } else {
        1
    };

    let frames = input.len() / frame_bytes;
    let pending_arc = enable_sco_uplink_pending();
    let mut pending = pending_arc.lock().unwrap();

    for frame_idx in (0..frames).step_by(step) {
        let offset = frame_idx * frame_bytes;
        // Use the first channel when the HU ever exposes stereo/dual-mic PCM.
        pending.extend_from_slice(&input[offset..offset + 2]);

        while pending.len() >= SCO_UPLINK_PACKET_BYTES {
            let packet: Vec<u8> = pending.drain(..SCO_UPLINK_PACKET_BYTES).collect();
            drop(pending);
            push_sco_uplink_packet(packet, capacity);
            pending = pending_arc.lock().unwrap();
        }
    }
}


fn audio_metrics_s16le(input: &[u8]) -> (i16, u128, u64, f64) {
    let mut peak = 0i16;
    let mut energy = 0u128;
    let mut samples = 0u64;

    for chunk in input.chunks_exact(2) {
        let sample = i16::from_le_bytes([chunk[0], chunk[1]]) as i32;
        let abs = sample.unsigned_abs().min(i16::MAX as u32) as i16;
        peak = peak.max(abs);
        energy = energy.saturating_add((sample as i128 * sample as i128) as u128);
        samples += 1;
    }

    (peak, energy, samples, rms_from_energy(energy, samples))
}

fn rms_from_energy(energy: u128, samples: u64) -> f64 {
    if samples == 0 {
        0.0
    } else {
        ((energy as f64) / samples as f64).sqrt()
    }
}

fn log_sco_socket_info(fd: RawFd) {
    match getsockopt_value::<ScoOptions>(fd, SOL_SCO, SCO_OPTIONS) {
        Ok(v) => info!("{} SCO_OPTIONS mtu={}", NAME, v.mtu),
        Err(e) => debug!("{} SCO_OPTIONS unavailable: {}", NAME, e),
    }

    match getsockopt_value::<ScoConnInfo>(fd, SOL_SCO, SCO_CONNINFO) {
        Ok(v) => info!(
            "{} SCO_CONNINFO hci_handle=0x{:04x} dev_class={:02x}:{:02x}:{:02x}",
            NAME,
            v.hci_handle,
            v.dev_class[0],
            v.dev_class[1],
            v.dev_class[2]
        ),
        Err(e) => debug!("{} SCO_CONNINFO unavailable: {}", NAME, e),
    }

    match getsockopt_value::<BtVoice>(fd, SOL_BLUETOOTH, BT_VOICE) {
        Ok(v) => info!(
            "{} BT_VOICE setting=0x{:04x} ({})",
            NAME,
            v.setting,
            describe_bt_voice(v.setting)
        ),
        Err(e) => debug!("{} BT_VOICE unavailable: {}", NAME, e),
    }

    match getsockopt_int(fd, SOL_BLUETOOTH, BT_RCVMTU) {
        Ok(v) => info!("{} BT_RCVMTU={}", NAME, v),
        Err(e) => debug!("{} BT_RCVMTU unavailable: {}", NAME, e),
    }

    match getsockopt_int(fd, SOL_BLUETOOTH, BT_SNDMTU) {
        Ok(v) => info!("{} BT_SNDMTU={}", NAME, v),
        Err(e) => debug!("{} BT_SNDMTU unavailable: {}", NAME, e),
    }
}

fn getsockopt_value<T: Copy + Default>(fd: RawFd, level: libc::c_int, optname: libc::c_int) -> io::Result<T> {
    let mut value = T::default();
    let mut len = mem::size_of::<T>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            &mut value as *mut T as *mut libc::c_void,
            &mut len as *mut libc::socklen_t,
        )
    };

    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

fn getsockopt_int(fd: RawFd, level: libc::c_int, optname: libc::c_int) -> io::Result<i32> {
    getsockopt_value::<libc::c_int>(fd, level, optname)
}

fn describe_bt_voice(setting: u16) -> &'static str {
    // These are the common HCI voice-setting low bits used by Linux/BlueZ.
    // Exact transport codec is still best confirmed with HCI events, but this
    // is useful enough to distinguish the common CVSD path from transparent data.
    match setting & 0x0003 {
        0x0000 => "linear/input coding",
        0x0001 => "u-law/input coding",
        0x0002 => "a-law/input coding",
        0x0003 => "reserved/input coding",
        _ => "unknown",
    }
}


/// Confirmed format for the current HSP/SCO path seen on the target phone/HU setup.
///
/// Linux exposes this SCO socket as linear PCM (`BT_VOICE=0x0060`). Runtime
/// logs should still be trusted first, but the observed stream is stable:
/// 60-byte packets at ~266.7 packets/sec = ~16000 B/s = 8000 s16 mono samples/sec.
pub const SCO_LINEAR_PCM_SAMPLE_RATE_HZ: u32 = 8_000;
pub const SCO_LINEAR_PCM_CHANNELS: u16 = 1;
pub const SCO_LINEAR_PCM_BITS_PER_SAMPLE: u16 = 16;

/// Target format for the HU media sink that advertised PCM MEDIA:
/// 48 kHz, signed 16-bit, stereo.
pub const AA_MEDIA_PCM_SAMPLE_RATE_HZ: u32 = 48_000;
pub const AA_MEDIA_PCM_CHANNELS: u16 = 2;
pub const AA_MEDIA_PCM_BITS_PER_SAMPLE: u16 = 16;

#[derive(Debug, Default)]
pub struct DownlinkResamplerState {
    last_sample: Option<i16>,
}

/// Convert one chunk of SCO linear PCM (`s16le`, mono, 8 kHz) into the
/// simplest AA media PCM shape (`s16le`, stereo, 48 kHz).
///
/// The default `Repeat` mode preserves the proven first implementation: each
/// 8 kHz sample becomes six identical 48 kHz stereo frames. `Linear` keeps the
/// same output size/timing but interpolates between adjacent samples, which can
/// reduce rough edges without pulling in a resampler dependency.
pub fn sco_s16le_mono_8k_to_aa_pcm_s16le_stereo_48k(
    input: &[u8],
    output: &mut Vec<u8>,
    resampler: BtScoMediaBridgeResampler,
    state: &mut DownlinkResamplerState,
) {
    let even_len = input.len() & !1;

    // Each input i16 sample becomes 6 stereo frames.
    // 2 input bytes -> 6 * 2 channels * 2 output bytes = 24 output bytes.
    output.reserve((even_len / 2) * 24);

    for sample in input[..even_len].chunks_exact(2) {
        let current = i16::from_le_bytes([sample[0], sample[1]]);
        match resampler {
            BtScoMediaBridgeResampler::Repeat => {
                push_stereo_repeated_sample(output, current);
            }
            BtScoMediaBridgeResampler::Linear => {
                let previous = state.last_sample.unwrap_or(current);
                push_stereo_linear_6x(output, previous, current);
            }
        }
        state.last_sample = Some(current);
    }
}

fn push_stereo_repeated_sample(output: &mut Vec<u8>, sample: i16) {
    let bytes = sample.to_le_bytes();
    for _ in 0..6 {
        output.extend_from_slice(&bytes);
        output.extend_from_slice(&bytes);
    }
}

fn push_stereo_linear_6x(output: &mut Vec<u8>, previous: i16, current: i16) {
    let previous = previous as i32;
    let current = current as i32;
    let delta = current - previous;

    // Six output frames bridge the previous sample to the current sample.
    // step=6 lands exactly on `current`, preserving timing and chunk size.
    for step in 1..=6 {
        let interpolated = previous + (delta * step) / 6;
        let sample = interpolated.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        let bytes = sample.to_le_bytes();
        output.extend_from_slice(&bytes);
        output.extend_from_slice(&bytes);
    }
}

fn format_bdaddr(addr: BdAddr) -> String {
    let b = addr.b;
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        b[5], b[4], b[3], b[2], b[1], b[0]
    )
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sco_converter_expands_8k_mono_to_48k_stereo() {
        // Two input samples: 0x0001 and 0x0002.
        let input = [0x01, 0x00, 0x02, 0x00];
        let mut output = Vec::new();

        sco_s16le_mono_8k_to_aa_pcm_s16le_stereo_48k(
            &input,
            &mut output,
            BtScoMediaBridgeResampler::Repeat,
            &mut DownlinkResamplerState::default(),
        );

        // 2 mono samples * 6x upsample * 2 stereo channels * 2 bytes.
        assert_eq!(output.len(), 48);

        // First upsampled stereo frame should be L=sample1, R=sample1.
        assert_eq!(&output[0..4], &[0x01, 0x00, 0x01, 0x00]);

        // The seventh stereo frame starts the second input sample.
        let second_sample_offset = 6 * 2 * 2;
        assert_eq!(
            &output[second_sample_offset..second_sample_offset + 4],
            &[0x02, 0x00, 0x02, 0x00]
        );
    }

    #[test]
    fn sco_converter_ignores_trailing_odd_byte() {
        let input = [0x01, 0x00, 0xff];
        let mut output = Vec::new();

        sco_s16le_mono_8k_to_aa_pcm_s16le_stereo_48k(
            &input,
            &mut output,
            BtScoMediaBridgeResampler::Repeat,
            &mut DownlinkResamplerState::default(),
        );

        assert_eq!(output.len(), 24);
    }
}
