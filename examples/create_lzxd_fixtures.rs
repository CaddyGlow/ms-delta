//! Reproduce original encoder vectors and verify them with an external oracle.
use ms_delta::{Limits, create_lzxd};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let oracle = PathBuf::from(args.next().ok_or("oracle path required")?);
    let directory = PathBuf::from(args.next().ok_or("output directory required")?);
    fs::create_dir_all(&directory)?;
    let mut state = 5071u32;
    let random: Vec<u8> = (0..4096)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let cases = [
        ("random", Vec::new(), random[..2049].to_vec()),
        ("reference", random.clone(), random[97..1634].to_vec()),
        ("overlap", Vec::new(), vec![b'z'; 70000]),
        (
            "frame-boundary",
            Vec::new(),
            (0..32769).map(|i| (i % 251) as u8).collect(),
        ),
    ];
    let mut results = Vec::new();
    for (name, source, target) in cases {
        let source_path = directory.join(format!("{name}.source"));
        let target_path = directory.join(format!("{name}.target"));
        fs::write(&source_path, &source)?;
        fs::write(&target_path, &target)?;
        for order in 17..=25 {
            let patch = create_lzxd(&source, &target, order, &Limits::default())?;
            let delta_path = directory.join(format!("{name}-{order}.delta"));
            let output = directory.join("oracle-output.tmp");
            fs::write(&delta_path, &patch)?;
            let status = Command::new(&oracle)
                .arg(&delta_path)
                .arg(&source_path)
                .arg(&output)
                .arg(order.to_string())
                .arg(target.len().to_string())
                .status()?;
            if !status.success() || fs::read(&output)? != target {
                return Err("independent oracle mismatch".into());
            }
            fs::remove_file(&output)?;
            results.push(serde_json::json!({"name":name,"window_order":order,"source_bytes":source.len(),"target_bytes":target.len(),"delta_bytes":patch.len(),"source_sha256":hash(&source),"target_sha256":hash(&target),"delta_sha256":hash(&patch),"oracle_exit":0}));
        }
    }
    let manifest = serde_json::json!({"oracle":"libmspack lzxd reference decoder external wrapper","upstream_commit":"55d501976171397ccd5d5a7a1ca7da065b1d9a06","oracle_binary_sha256":hash(&fs::read(&oracle)?),"environment":std::env::consts::OS,"seed":5071,"cases":results});
    fs::write(
        directory.join("oracle-results.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}
