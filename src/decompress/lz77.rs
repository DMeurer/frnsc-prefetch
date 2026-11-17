use forensic_rs::err::{ForensicError, ForensicResult};

pub fn decompress(in_buf: &[u8], out_buf: &mut Vec<u8>) -> ForensicResult<()> {
    // The decompressed size from the header: a match never writes past it.
    let output_size = out_buf.capacity();
    let byte = |at: usize| {
        in_buf.get(at).copied().ok_or_else(|| {
            ForensicError::bad_format_str("decompress_LZ77(): The data ends inside a match")
        })
    };
    let le = |at: usize, n: usize| -> ForensicResult<u32> {
        (0..n).try_fold(0u32, |v, k| Ok(v | (byte(at + k)? as u32) << (8 * k)))
    };
    let mut buffered_flags = 0;
    let mut buffered_flag_count = 0;
    let mut input_position = 0;
    let mut last_length_half_byte = 0;
    loop {
        if input_position >= in_buf.len() {
            return Ok(());
        }
        if buffered_flag_count == 0 {
            buffered_flags = le(input_position, 4)?;
            input_position += 4;
            buffered_flag_count = 32;
        }
        buffered_flag_count -= 1;
        if (buffered_flags & (1 << buffered_flag_count)) == 0 {
            if input_position == in_buf.len() {
                return Ok(());
            }
            out_buf.push(byte(input_position)?);
            input_position += 1;
        } else {
            if input_position == in_buf.len() {
                return Ok(());
            }
            let match_bytes = le(input_position, 2)?;
            input_position += 2;
            let mut match_length = match_bytes % 8;
            let match_offset = (match_bytes / 8) + 1;
            if match_length == 7 {
                if last_length_half_byte == 0 {
                    match_length = (byte(input_position)? as u32) % 16;
                    last_length_half_byte = input_position;
                    input_position += 1;
                } else {
                    match_length = (byte(last_length_half_byte)? as u32) / 16;
                    last_length_half_byte = 0;
                }
                if match_length == 15 {
                    match_length = byte(input_position)? as u32;
                    input_position += 1;
                    if match_length == 255 {
                        match_length = le(input_position, 2)?;
                        input_position += 2;
                        if match_length == 0 {
                            match_length = le(input_position, 4)?;
                            input_position += 4;
                        }
                        if match_length < 22 {
                            return Err(ForensicError::bad_format_str(
                                "decompress_LZ77(): Invalid match length, must be greater than 22",
                            ));
                        }
                        match_length -= 22;
                    }
                    match_length += 15;
                }
                match_length += 7;
            }
            match_length = match_length.saturating_add(3);
            let from = out_buf
                .len()
                .checked_sub(match_offset as usize)
                .ok_or_else(|| {
                    ForensicError::bad_format_str(
                        "decompress_LZ77(): A match points before the start of the data",
                    )
                })?;
            for k in 0..match_length as usize {
                if out_buf.len() >= output_size {
                    break;
                }
                out_buf.push(out_buf[from + k]);
            }
        }
    }
}

#[test]
fn basic_lz77_decompression() {
    let uncompressed = b"abcdefghijklmnopqrstuvwxyz";
    let encoded: [u8; 30] = [
        0x3f, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
        0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
    ];

    let mut decoded_value = Vec::with_capacity(1024);
    decompress(&encoded, &mut decoded_value).unwrap();
    assert_eq!(uncompressed, &decoded_value[..]);
}

#[test]
fn basic_lz77_decompression_2() {
    let uncompressed = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
    let encoded: [u8; 13] = [
        0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01,
    ];

    let mut decoded_value = Vec::with_capacity(1024);
    decompress(&encoded, &mut decoded_value).unwrap();
    assert_eq!(uncompressed, &decoded_value[..]);
}

#[test]
fn a_match_before_the_start_is_refused() {
    // One literal, then a match 1,000 bytes back.
    let encoded: [u8; 7] = [0x00, 0x00, 0x00, 0x40, 0x61, 0x38, 0x1f];
    let mut decoded_value = Vec::with_capacity(1024);
    assert!(decompress(&encoded, &mut decoded_value).is_err());
}

#[test]
fn data_that_ends_inside_a_match_is_refused() {
    // A match whose length continues in a byte that isn't there.
    let encoded: [u8; 7] = [0x00, 0x00, 0x00, 0x40, 0x61, 0x07, 0x00];
    let mut decoded_value = Vec::with_capacity(1024);
    assert!(decompress(&encoded, &mut decoded_value).is_err());
}

#[test]
fn a_match_stops_at_the_decompressed_size() {
    // A literal, then a match of 4 GiB.
    let encoded: [u8; 15] = [
        0x00, 0x00, 0x00, 0x40, 0x61, 0x07, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    ];
    let mut decoded_value = Vec::with_capacity(64);
    decompress(&encoded, &mut decoded_value).unwrap();
    assert_eq!(decoded_value.len(), 64);
}
