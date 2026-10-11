use ms_delta::{Limits, pa30::apply_pa30};
use sha2::{Digest, Sha256};

#[test]
#[ignore = "requires cache-only SSU5071 members in WINDOWS_DELTA_SSU5071_DIR"]
fn real_ssu5071_pe_chain_matches_native_and_cix_using_rust_bases() {
    let directory = std::env::var_os("WINDOWS_DELTA_SSU5071_DIR").expect("set patch directory");
    let directory = std::path::Path::new(&directory);
    let cases = [
        (
            "0",
            None,
            1326048,
            "b345f8c91d35801996c364420de41363924c8fd7894e16e520dfb560af966586",
            "884b19a15a672842b1d6a9abece35fdfb01989122cc7ec2f709d5df964b48f5e",
        ),
        (
            "1",
            Some(0),
            390152,
            "7b1d3052a147218ee2f3c528c016d7c5b95c12a3940ca1051b8687f75ecb3bf5",
            "c0978b8804f54b937af17309d98b034cad0adf32c689f98cf3b889cd14a5f434",
        ),
        (
            "2",
            Some(0),
            2685408,
            "3a7a0a3c3ac9f0b4e9a85824366ea0dd9ce7b61aca9ad206443bb254f290061f",
            "15c485eb603a188e99d2f8973b98f1a9064653dac515e7b85d6b21b96fa41a94",
        ),
        (
            "10",
            Some(1),
            33800,
            "7bd0b0958a4d8cb2a176e3512c3edbdbf89d0240ff6ccd012a6a04bb01fb2346",
            "9653df46b49b8c7a6b6b11be40f57f3b02a34feab56f35746c2d2efa94c12d1c",
        ),
    ];
    let mut targets: Vec<Vec<u8>> = Vec::new();
    for (member, basis, size, patch_hash, target_hash) in cases {
        let patch = std::fs::read(directory.join(member)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&patch)),
            patch_hash,
            "patch {member}"
        );
        let source = basis.map_or(&[][..], |index| targets[index].as_slice());
        let target = apply_pa30(source, &patch, &Limits::default()).unwrap();
        assert_eq!(target.len(), size, "target {member}");
        assert_eq!(
            format!("{:x}", Sha256::digest(&target)),
            target_hash,
            "target {member}"
        );
        targets.push(target);
    }
}

#[test]
#[ignore = "requires cache-only SSU5071 CAB member 0 in WINDOWS_DELTA_SSU5071_PATCH"]
fn real_ssu5071_raw_patch_matches_native_and_cix() {
    let path = std::env::var_os("WINDOWS_DELTA_SSU5071_PATCH").expect("set patch path");
    let patch = std::fs::read(path).unwrap();
    assert_eq!(patch.len(), 530301);
    assert_eq!(
        format!("{:x}", Sha256::digest(&patch)),
        "b345f8c91d35801996c364420de41363924c8fd7894e16e520dfb560af966586"
    );
    let target = apply_pa30(&[], &patch, &Limits::default()).unwrap();
    assert_eq!(target.len(), 1326048);
    assert_eq!(
        format!("{:x}", Sha256::digest(&target)),
        "884b19a15a672842b1d6a9abece35fdfb01989122cc7ec2f709d5df964b48f5e"
    );
}
