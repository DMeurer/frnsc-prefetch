use forensic_rs::{
    core::fs::{ChRootFileSystem, StdVirtualFS},
    traits::{
        forensic::{IntoActivity, IntoTimeline},
        vfs::VirtualFileSystem,
    },
    utils::time::Filetime,
};
use std::path::Path;

use crate::prefetch::{
    read_prefetch_file_compressed, read_prefetch_file_no_compressed, read_prefetch_form_fs,
};

#[test]
fn should_parse_all_prefetchs_from_fs() {
    let mut fs = ChRootFileSystem::new("./artifacts/17", Box::new(StdVirtualFS::new()));
    read_prefetch_form_fs(&mut fs).expect("Must read all prefetch from filesystem");
}

#[test]
fn should_parse_prefetch_v17() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/17/C/Windows/Prefetch/CMD.EXE-087B4001.pf",
        ))
        .unwrap();
    let a = read_prefetch_file_no_compressed("CMD.EXE-087B4001.pf", file).unwrap();
    println!("{:?}", a);
}
#[test]
fn should_parse_prefetch_v30_2() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf",
        ))
        .unwrap();
    read_prefetch_file_compressed("RUST_OUT.EXE-5D2C8541.pf", file).unwrap();
}
#[test]
fn should_parse_prefetch_v30() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/30/C/Windows/Prefetch/CMD.EXE-D269B812.pf",
        ))
        .unwrap();
    read_prefetch_file_compressed("CMD.EXE-D269B812.pf", file).unwrap();
}

#[test]
fn should_parse_prefetch_v26() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/26/C/Windows/Prefetch/CMD.EXE-4A81B364.pf",
        ))
        .unwrap();
    read_prefetch_file_no_compressed("CMD.EXE-4A81B364.pf", file).unwrap();
}

#[test]
fn should_parse_prefetch_v23() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf",
        ))
        .unwrap();
    read_prefetch_file_no_compressed("NOTEPAD.EXE-D8414F97.pf", file).unwrap();
}

#[test]
fn should_parse_prefetch_v30_powershell() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/30/C/Windows/Prefetch/POWERSHELL.EXE-AE8EDC9B.pf",
        ))
        .unwrap();
    let pref = read_prefetch_file_compressed("POWERSHELL.EXE-AE8EDC9B.pf", file).unwrap();
    let mut forensic_data = pref.timeline();
    let event = forensic_data.next().unwrap();
    println!("{:?}", event);
    let mut forensic_data = pref.activity();
    let activity = forensic_data.next().unwrap();
    println!("Activity: {:?}", activity);
}

#[test]
fn should_parse_prefetch_v30_cmd() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/30/C/Windows/Prefetch/CMD.EXE-6D6290C5.pf",
        ))
        .unwrap();
    let pref = read_prefetch_file_compressed("CMD.EXE-6D6290C5.pf", file).unwrap();
    //println!("{:?}", pref);
    assert_eq!(4, pref.run_count);
    assert_eq!(4, pref.last_run_times.len());
    assert_eq!(Filetime::new(133515874611440142), pref.last_run_times[0]); // 5 February 2024 6:17:41
    assert_eq!(Filetime::new(133515874591645855), pref.last_run_times[1]); // 5 February 2024 6:17:39
    assert_eq!(Filetime::new(133515561632524658), pref.last_run_times[2]); // 4 February 2024 21:36:03
    assert_eq!(Filetime::new(133514937170602624), pref.last_run_times[3]); // 4 February 2024 4:15:17
}

#[test]
#[ignore]
fn should_parse_current_prefetches() {
    let mut fs = StdVirtualFS::new();
    let _pref = read_prefetch_form_fs(&mut fs).expect("Must read all prefetch from filesystem");
    //println!("{:?}", pref);
}

#[test]
fn should_not_hang_on_corrupt_prefetch() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/corrupt/SEARCHPROTOCOLHOST.EXE-AFAD3EF9.pf",
        ))
        .unwrap();
    assert!(read_prefetch_file_compressed("SEARCHPROTOCOLHOST.EXE-AFAD3EF9.pf", file).is_err());
}

#[test]
fn utf16_text_stays_inside_its_bytes() {
    // Four bytes without a NUL: a transmute to &[u16] kept the length 4 and read 4 bytes on.
    let buffer = b"A\0B\0C\0D\0";
    assert_eq!(crate::common::utf16_at_offset(buffer, 0, 4).unwrap(), "AB");
    assert_eq!(crate::common::utf16_at_offset(buffer, 0, 3).unwrap(), "A");
}

#[test]
fn names_are_read_by_their_character_counts() {
    // Loaded file names and device paths store a count of UTF-16 characters, not bytes.
    let mut fs = StdVirtualFS::new();
    for (v, f, volume) in [
        ("23", "NOTEPAD.EXE-D8414F97.pf", "\\DEVICE\\HARDDISKVOLUME2"),
        ("17", "CMD.EXE-087B4001.pf", "\\DEVICE\\HARDDISKVOLUME1"),
    ] {
        let path = format!("./artifacts/{v}/C/Windows/Prefetch/{f}");
        let pref = read_prefetch_file_no_compressed(f, fs.open(Path::new(&path)).unwrap()).unwrap();
        assert_eq!(
            pref.metrics[0].file,
            format!("{volume}\\WINDOWS\\SYSTEM32\\NTDLL.DLL")
        );
        assert_eq!(pref.volume[0].device_path, volume);
    }
}

#[test]
fn prefetch_files_over_one_megabyte_parse() {
    // vss's NTOSBOOT-B00DFAAD.pf is 1.8 MB; here a real file padded past the old 1,000,000.
    let mut data =
        std::fs::read("./artifacts/23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf").unwrap();
    data.resize(1_100_000, 0);
    let tmp = TempFile::new("large-NOTEPAD.EXE-D8414F97.pf", &data);
    let file = StdVirtualFS::new().open(&tmp.0).unwrap();
    let pref = read_prefetch_file_no_compressed("NOTEPAD.EXE-D8414F97.pf", file);
    assert_eq!(pref.unwrap().name, "NOTEPAD.EXE");
}

#[test]
fn a_huge_decompressed_size_is_refused() {
    let mut data =
        std::fs::read("./artifacts/30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf").unwrap();
    data[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    let tmp = TempFile::new("huge-RUST_OUT.EXE-5D2C8541.pf", &data);
    let file = StdVirtualFS::new().open(&tmp.0).unwrap();
    let pref = read_prefetch_file_compressed("RUST_OUT.EXE-5D2C8541.pf", file);
    let err = pref.expect_err("4 GiB is no prefetch file").to_string();
    assert!(err.contains("decompressed size"), "{err}");
}

/// A file in the temp dir, named per process so parallel runs don't collide, removed on drop even if the test fails.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(name: &str, data: &[u8]) -> Self {
        let tmp = Self(
            std::env::temp_dir().join(format!("frnsc-prefetch-{}-{name}", std::process::id())),
        );
        std::fs::write(&tmp.0, data).unwrap();
        tmp
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn a_prefetch_shorter_than_its_header_is_refused() {
    // A compressed file whose header claims a decompressed size of 0, and a plain one cut short.
    let mut data =
        std::fs::read("./artifacts/30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf").unwrap();
    data[4..8].copy_from_slice(&0u32.to_le_bytes());
    let tmp = TempFile::new("empty-RUST_OUT.EXE-5D2C8541.pf", &data);
    let file = StdVirtualFS::new().open(&tmp.0).unwrap();
    assert!(read_prefetch_file_compressed("RUST_OUT.EXE-5D2C8541.pf", file).is_err());

    let data = std::fs::read("./artifacts/23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf").unwrap();
    let tmp = TempFile::new("short-NOTEPAD.EXE-D8414F97.pf", &data[..40]);
    let file = StdVirtualFS::new().open(&tmp.0).unwrap();
    assert!(read_prefetch_file_no_compressed("NOTEPAD.EXE-D8414F97.pf", file).is_err());
}

#[test]
fn an_offset_and_size_that_wrap_are_refused() {
    // Version 23: the file information starts at 84. An offset near 4 GiB plus a size of 4 KiB
    // wraps to 0 in 32 bits, so the end passed the length check while the start did not.
    let notepad =
        std::fs::read("./artifacts/23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf").unwrap();
    let put =
        |data: &mut Vec<u8>, at: usize, v: u32| data[at..at + 4].copy_from_slice(&v.to_le_bytes());
    // The file names of the metrics.
    let mut data = notepad.clone();
    put(&mut data, 84 + 16, 0xFFFF_F000);
    put(&mut data, 84 + 20, 0x1000);
    let tmp = TempFile::new("wrap-strings-NOTEPAD.EXE-D8414F97.pf", &data);
    let file = StdVirtualFS::new().open(&tmp.0).unwrap();
    assert!(read_prefetch_file_no_compressed("NOTEPAD.EXE-D8414F97.pf", file).is_err());
    // The first volume's file references.
    let mut data = notepad;
    let volumes = u32::from_le_bytes(data[84 + 24..84 + 28].try_into().unwrap()) as usize;
    put(&mut data, volumes + 20, 0xFFFF_F000);
    put(&mut data, volumes + 24, 0x1000);
    let tmp = TempFile::new("wrap-volume-NOTEPAD.EXE-D8414F97.pf", &data);
    let file = StdVirtualFS::new().open(&tmp.0).unwrap();
    assert!(read_prefetch_file_no_compressed("NOTEPAD.EXE-D8414F97.pf", file).is_err());
}

#[test]
fn a_chunk_cut_after_its_huffman_table_is_refused() {
    // The header, the 256-byte table and 2 of the bit stream's 4 bytes.
    let data = std::fs::read("./artifacts/30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf").unwrap();
    let tmp = TempFile::new("cut-RUST_OUT.EXE-5D2C8541.pf", &data[..8 + 258]);
    let file = StdVirtualFS::new().open(&tmp.0).unwrap();
    assert!(read_prefetch_file_compressed("RUST_OUT.EXE-5D2C8541.pf", file).is_err());
}

#[test]
fn a_compressed_header_without_compression_parses() {
    // "MAM" with algorithm 0, then the size and the plain file.
    let plain = std::fs::read("./artifacts/23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf").unwrap();
    let mut data = b"MAM\0".to_vec();
    data.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    data.extend_from_slice(&plain);
    let tmp = TempFile::new("stored-NOTEPAD.EXE-D8414F97.pf", &data);
    let file = StdVirtualFS::new().open(&tmp.0).unwrap();
    let pref = read_prefetch_file_compressed("NOTEPAD.EXE-D8414F97.pf", file);
    assert_eq!(pref.unwrap().name, "NOTEPAD.EXE");
}

#[test]
fn counts_the_data_cannot_hold_are_refused() {
    // Version 17: the file information starts at 84. Each count claims far more entries than the
    // file has, which reserved gigabytes or read past the end.
    let cmd = std::fs::read("./artifacts/17/C/Windows/Prefetch/CMD.EXE-087B4001.pf").unwrap();
    let get = |data: &[u8], at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
    let put =
        |data: &mut Vec<u8>, at: usize, v: u32| data[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let mut metrics = cmd.clone();
    put(&mut metrics, 84 + 4, 0x0FFF_FFFF);
    // A trace count whose offset plus 12 bytes each wraps to an end below 12 in 32 bits.
    let mut traces = cmd.clone();
    let offset = get(&traces, 84 + 8) as u64;
    put(
        &mut traces,
        84 + 12,
        ((1u64 << 32) - offset).div_ceil(12) as u32,
    );
    let mut volumes = cmd;
    put(&mut volumes, 84 + 28, 0x0FFF_FFFF);
    for (name, data) in [
        ("metrics", metrics),
        ("traces", traces),
        ("volumes", volumes),
    ] {
        let tmp = TempFile::new(&format!("count-{name}-CMD.EXE-087B4001.pf"), &data);
        let file = StdVirtualFS::new().open(&tmp.0).unwrap();
        let pref = read_prefetch_file_no_compressed("CMD.EXE-087B4001.pf", file);
        assert!(pref.is_err(), "{name}");
    }
}

#[test]
fn a_prefetch_cut_inside_its_file_information_is_refused() {
    // Version 17 reads 64 bytes of file information after the 84-byte header.
    let data = std::fs::read("./artifacts/17/C/Windows/Prefetch/CMD.EXE-087B4001.pf").unwrap();
    let tmp = TempFile::new("cut-info-CMD.EXE-087B4001.pf", &data[..84 + 40]);
    let file = StdVirtualFS::new().open(&tmp.0).unwrap();
    assert!(read_prefetch_file_no_compressed("CMD.EXE-087B4001.pf", file).is_err());
}
