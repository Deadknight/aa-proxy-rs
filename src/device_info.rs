use anyhow::Result;
use std::fs;

/// Returns the SBC model string.
pub fn get_sbc_model() -> Result<String> {
    Ok(fs::read_to_string("/sys/firmware/devicetree/base/model")?
        .trim_end_matches(char::from(0))
        .trim()
        .to_string())
}

pub fn board_prefix() -> Option<&'static str> {
    option_env!("AA_PROXY_BOARD").filter(|value| !value.is_empty())
}
