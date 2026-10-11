//! Emit PE header and section metadata for observation scripts using the shared parser.

use std::{error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: pe_inspect FILE")?;
    let bytes = std::fs::read(path)?;
    let headers = hexspell::pe::view::PeHeaders::parse(&bytes)?;
    let count = usize::from(headers.coff.number_of_sections.value);
    if count > 4096 {
        return Err("excessive PE section count".into());
    }
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let section = headers.section(index)?;
        let name = bytes
            .get(section.name.offset..section.name.offset + 8)
            .ok_or("truncated section name")?;
        let name = name.split(|byte| *byte == 0).next().unwrap_or_default();
        sections.push(serde_json::json!({
            "name": String::from_utf8_lossy(name),
            "raw_size": section.size_of_raw_data.value,
            "raw_offset": section.pointer_to_raw_data.value,
            "rva": section.virtual_address.value,
            "virtual_size": section.virtual_size.value,
        }));
    }
    println!(
        "{}",
        serde_json::json!({"machine": headers.coff.machine.value, "sections": sections})
    );
    Ok(())
}
