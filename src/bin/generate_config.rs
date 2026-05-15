use aa_proxy_rs::config::{AppConfig, ConfigJson};
use serde_json::Value;
use std::path::PathBuf;
use std::{collections::BTreeMap, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting default config generation...");

    // Path to the generated .toml file, located relative to the
    // executable's directory (based on the target triple)
    let output_path: PathBuf = std::env::current_exe()?
        .parent()
        .ok_or("Unable to get parent directory of the binary")?
        .join("config.toml");

    println!("💾 Saving config to: {}", output_path.display());

    generate_config(output_path)?;
    println!("✅ Config generation completed successfully!");

    Ok(())
}

pub fn generate_config<P: AsRef<Path>>(output_path: P) -> Result<(), Box<dyn std::error::Error>> {
    let config_json: ConfigJson = AppConfig::load_config_json()?;
    let default_config = AppConfig::default();

    // Convert AppConfig into a serde_json::Value and collect it as a map
    let default_map: BTreeMap<String, Value> = serde_json::to_value(default_config)?
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let mut output = String::new();

    for section in config_json.titles {
        output.push_str(&format!("### {}\n", section.title.trim()));

        for (key, val) in section.values {
            // Write comment lines for each description line
            for line in val.description.lines() {
                output.push_str(&format!("  # {}\n", line.trim()));
            }

            // Get the default value from AppConfig (or a fallback default based on type)
            let default = default_map
                .get(&key)
                .map(|v| to_toml_value_string(v))
                .unwrap_or_else(|| match val.typ.as_str() {
                    "string" => r#""""#.to_string(),
                    "integer" => "0".to_string(),
                    "float" => "0.0".to_string(),
                    "boolean" => "false".to_string(),
                    "select" => {
                        if let Some(values) = &val.values {
                            format!(r#""{}""#, values.first().unwrap_or(&"".to_string()))
                        } else {
                            r#""""#.to_string()
                        }
                    }
                    "multi-select" => r#""""#.to_string(),
                    _ => r#""""#.to_string(),
                });

            // These values are generated at runtime on the actual device,
            // so we comment them out during config generation;
            // otherwise, we might accidentally force incorrect values.
            let commented: &str = {
                if key == "wifi_version" || key == "band" || key == "channel" {
                    "#"
                } else {
                    ""
                }
            };
            output.push_str(&format!("  {}{} = {}\n\n", commented, key, default));
        }
    }

    fs::write(&output_path, output)?;

    Ok(())
}

/// Converts a serde_json::Value into a TOML-compatible string representation
fn to_toml_value_string(value: &Value) -> String {
    match value {
        Value::String(s) => format!(r#""{}""#, s),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => r#""""#.to_string(),
        _ => format!(r#""{}""#, value), // fallback for other types
    }
}
