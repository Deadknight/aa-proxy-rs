use crate::config::BtScoMicEchoControl;
use simplelog::*;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const NAME: &str = "<i><bright-black> bt-sco-echo: </>";

#[derive(Debug, Clone)]
pub struct BtScoEchoSettings {
    pub control: BtScoMicEchoControl,
    pub mic_gain_percent: u32,
    pub duck_threshold: i16,
    pub duck_percent: u32,
    pub duck_hold_ms: u32,
}

impl Default for BtScoEchoSettings {
    fn default() -> Self {
        Self {
            control: BtScoMicEchoControl::Off,
            mic_gain_percent: 100,
            duck_threshold: 700,
            duck_percent: 35,
            duck_hold_ms: 180,
        }
    }
}

struct EchoState {
    settings: BtScoEchoSettings,
    downlink_active_until: Option<Instant>,
    last_downlink_peak: i16,
    generation: u64,
}

impl Default for EchoState {
    fn default() -> Self {
        Self {
            settings: BtScoEchoSettings::default(),
            downlink_active_until: None,
            last_downlink_peak: 0,
            generation: 0,
        }
    }
}

static ECHO_STATE: OnceLock<Arc<Mutex<EchoState>>> = OnceLock::new();

fn state() -> Arc<Mutex<EchoState>> {
    ECHO_STATE
        .get_or_init(|| Arc::new(Mutex::new(EchoState::default())))
        .clone()
}

pub fn configure(settings: BtScoEchoSettings) {
    let state = state();
    let mut state = state.lock().unwrap();
    let changed = state.settings.control != settings.control
        || state.settings.mic_gain_percent != settings.mic_gain_percent
        || state.settings.duck_threshold != settings.duck_threshold
        || state.settings.duck_percent != settings.duck_percent
        || state.settings.duck_hold_ms != settings.duck_hold_ms;

    state.settings = settings.clone();
    if changed {
        debug!(
            "{} configured mic echo_control={}, mic_gain={}%, duck_threshold={}, duck_percent={}%, duck_hold={}ms",
            NAME,
            settings.control,
            settings.mic_gain_percent,
            settings.duck_threshold,
            settings.duck_percent,
            settings.duck_hold_ms,
        );
    }
}

pub fn reset_for_sco_generation(generation: u64) {
    let state = state();
    let mut state = state.lock().unwrap();
    state.generation = generation;
    state.downlink_active_until = None;
    state.last_downlink_peak = 0;
    debug!("{} reset echo state for SCO generation={}", NAME, generation);
}

pub fn observe_downlink_sco_8k_mono(input: &[u8]) {
    if input.is_empty() {
        return;
    }

    let peak = peak_s16le(input);
    let state = state();
    let mut state = state.lock().unwrap();
    state.last_downlink_peak = peak;

    if state.settings.control != BtScoMicEchoControl::Ducking {
        return;
    }

    let threshold = state.settings.duck_threshold.max(0) as i16;
    if peak >= threshold {
        state.downlink_active_until = Some(
            Instant::now() + Duration::from_millis(state.settings.duck_hold_ms.max(1) as u64),
        );
    }
}

pub fn process_mic_8k_samples(samples: &mut [i16]) {
    if samples.is_empty() {
        return;
    }

    let state_arc = state();
    let state = state_arc.lock().unwrap();
    let settings = state.settings.clone();

    match settings.control {
        BtScoMicEchoControl::Off => {}
        BtScoMicEchoControl::Ducking => apply_ducking_if_active(samples, &state, &settings),
    }

    apply_gain(samples, settings.mic_gain_percent);
}

fn apply_ducking_if_active(samples: &mut [i16], state: &EchoState, settings: &BtScoEchoSettings) {
    let active = state
        .downlink_active_until
        .map(|until| Instant::now() <= until)
        .unwrap_or(false);

    if !active {
        return;
    }

    let percent = settings.duck_percent.min(100);
    if percent >= 100 {
        return;
    }

    for sample in samples.iter_mut() {
        *sample = scale_i16(*sample, percent as i32);
    }
}

fn apply_gain(samples: &mut [i16], gain_percent: u32) {
    let gain_percent = gain_percent.max(1);
    if gain_percent == 100 {
        return;
    }

    for sample in samples.iter_mut() {
        *sample = scale_i16(*sample, gain_percent as i32);
    }
}

fn scale_i16(sample: i16, percent: i32) -> i16 {
    let scaled = sample as i32 * percent / 100;
    scaled.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

fn peak_s16le(input: &[u8]) -> i16 {
    let mut peak: i32 = 0;
    for bytes in input.chunks_exact(2) {
        let sample = i16::from_le_bytes([bytes[0], bytes[1]]) as i32;
        peak = peak.max(sample.abs());
    }
    peak.min(i16::MAX as i32) as i16
}
