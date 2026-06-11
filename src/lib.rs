//! AES - Advanced Encryption Standard

// GF(2^8) operations
pub fn xtimes(a: u8) -> u8 {
    let mut b = a as u16;
    b <<= 1;
    ((b & 0xff) ^ (if b & 0x100 == 0x100 {0x1b} else {0})) as u8
}

pub fn gf8_mul(a: u8, b: u8) -> u8 {
    let mut buffer: [u8; 8] = [a, 0, 0, 0, 0, 0, 0, 0];
    for i in 0..7 {
        buffer[i + 1] = xtimes(buffer[i]);
    }

    let mut result = 0u8;
    for i in 0..8 {
        if (b >> i) & 0x1 == 0x1 {
            result ^= buffer[i];
        }
    }
    result
}

pub fn gf8_sum(a: u8, b: u8) -> u8 {
    a ^ b
}


// 
pub const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

pub const INVSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

pub const MATRIX: [u8; 16] = [2, 3, 1, 1,
                              1, 2, 3, 1,
                              1, 1, 2, 3,
                              3, 1, 1, 2];

pub const INVMATRIX: [u8; 16] = [0xe, 0xb, 0xd, 9,
                                 9, 0xe, 0xb, 0xd,
                                 0xd, 9, 0xe, 0xb,
                                 0xb, 0xd, 9, 0xe];

pub const OFFSETS: [isize; 4] = [0, 1, 2, 3];

pub const INVOFFSETS: [isize; 4] = [0, -1, -2, -3];

pub const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
];

pub fn sub_word(dword: u32, r#box: & [u8; 256]) -> u32 {
    let mut bytes = dword.to_be_bytes();
    for i in 0..4 {
        bytes[i] = r#box[bytes[i] as usize];
    }
    u32::from_be_bytes(bytes)
}

pub fn sub_bytes(state: &mut [u32], r#box: & [u8; 256]) -> () {

    for dword in state {
        let mut bytes = dword.to_be_bytes();
        for byte in &mut bytes {
            *byte = r#box[*byte as usize];
        }
        *dword = u32::from_be_bytes(bytes);
    }
}


pub fn mix_columns(state: &mut [u32], matrix: &[u8; 16]) -> () {
    for word in state {
        let bytes = word.to_be_bytes();
        let mut result: [u8; 4] = [0, 0, 0, 0];
        for i in 0..4 {
            result[i] = gf8_mul(matrix[4 * i], bytes[0]) ^ gf8_mul(matrix[4 * i + 1], bytes[1]) ^ gf8_mul(matrix[4 * i + 2], bytes[2]) ^ gf8_mul(matrix[4 * i + 3], bytes[3]);
        }
        *word = u32::from_be_bytes(result);
    }
}


pub fn add_round_key(state: &mut [u32], key: &[u32], l: usize) -> () {
    for i in 0..state.len() {
        state[i] ^= key[l + i];
    }
}

pub fn shift_rows(state: &mut [u32], offsets: &[isize; 4]) {
    let l = state.len();
    for ridx in 0..4 {
        let mut row = Vec::<u8>::with_capacity(l);
        for word in state.iter() {
            row.push(word.to_be_bytes()[ridx]);
        }
        row.rotate_left(offsets[ridx].rem_euclid(l as isize) as usize);
        for i in 0..state.len() {
            let mut bytes = state[i].to_be_bytes();
            bytes[ridx] = row[i];
            state[i] = u32::from_be_bytes(bytes);
        }
    }
}

pub fn key_expansion(key: &[u32], nb: usize, nr: usize, r#box: & [u8; 256], rcon: &'static [u32]) -> Vec<u32> {
    let mut w = Vec::<u32>::with_capacity(nb * (nr + 1));
    w.extend_from_slice(key);
    let mut i = w.len();
    while i < nb * (nr + 1) {
        let mut temp = w[i - 1];
        if i % key.len() == 0 {
            temp = sub_word(temp.rotate_left(8), r#box) ^ rcon[i / key.len() - 1];
        } else if key.len() > 6 && i % key.len() == 4 {
            temp = sub_word(temp, r#box);
        }
        w.push(w[i - key.len()] ^ temp);
        i += 1;
    }
    w
}

pub fn key_expansion_bytes(key: &[u8], nb: usize) -> Result<Vec<u32>, &'static str> {
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err("`rijndael` expected 16 | 24 | 32 bytes key sizes.");
    }
    let k = key.chunks_exact(4).map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap())).collect::<Vec<u32>>();
    Ok(key_expansion(&k, nb, std::cmp::max(nb, key.len() / 4) + 6, &self::SBOX, &self::RCON))
}

pub fn cipher(state: &mut [u32], w: &[u32], nr: usize, r#box: &[u8; 256], matrix: &[u8; 16], offsets: &[isize; 4]) {

    add_round_key(state, w, 0);
    for ridx in 1..nr {
        sub_bytes(state, r#box);
        shift_rows(state, offsets);
        mix_columns(state, matrix);
        add_round_key(state, w, state.len() * ridx);
    }
    sub_bytes(state, r#box);
    shift_rows(state, offsets);
    add_round_key(state, w, state.len() * nr);
}

pub fn inv_cipher(state: &mut [u32], w: &[u32], nr: usize, r#box: &[u8; 256], matrix: &[u8; 16], offsets: &[isize; 4]) {
    add_round_key(state, w, state.len() * nr);
    for ridx in (1..nr).rev() {
        shift_rows(state, offsets);
        sub_bytes(state, r#box);
        add_round_key(state, w, state.len() * ridx);
        mix_columns(state, matrix);
    }
    shift_rows(state, offsets);
    sub_bytes(state, r#box);
    add_round_key(state, w, 0);
}


pub fn encrypt_bytes(bytes: &mut [u8], w: &[u32]) -> Result<(), &'static str> {
    if !matches!(bytes.len(), 16 | 24 | 32) {
        return Err("`rijndael` expected 16 | 24 | 32 bytes state.");
    }
    let nb = bytes.len() / 4;
    let nr = w.len() / nb - 1;
    if w.len() % nb != 0 {
        return Err("`rijndael` expanded key length supposed to be state length multiple.");
    } else if nr < 10 || 14 < nr {
        return Err("`rijndael` number of rounds derived from expanded key invalid.");
    }
    let mut state = bytes.chunks_exact(4).map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap())).collect::<Vec<u32>>();
    cipher(&mut state, w, nr, &self::SBOX, &self::MATRIX, &self::OFFSETS);
    for i in 0..state.len() {
        bytes[4 * i..4 * (i + 1)].copy_from_slice(&state[i].to_be_bytes());
    }
    Ok(())
}

pub fn decrypt_bytes(bytes: &mut [u8], w: &[u32]) -> Result<(), &'static str> {
    if !matches!(bytes.len(), 16 | 24 | 32) {
        return Err("`rijndael` expected 16 | 24 | 32 bytes state.");
    }
    let nb = bytes.len() / 4;
    let nr = w.len() / nb - 1;
    if w.len() % nb != 0 {
        return Err("`rijndael` expanded key length supposed to be state length multiple.");
    } else if nr < 10 || 14 < nr {
        return Err("`rijndael` number of rounds derived from expanded key invalid.");
    }
    let mut state = bytes.chunks_exact(4).map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap())).collect::<Vec<u32>>();
    inv_cipher(&mut state, w, nr, &self::INVSBOX, &self::INVMATRIX, &self::INVOFFSETS);
    for i in 0..state.len() {
        bytes[4 * i..4 * (i + 1)].copy_from_slice(&state[i].to_be_bytes());
    }
    Ok(())
}


pub mod aes {
    
    pub fn encrypt_bytes(bytes: &mut [u8], w: &[u32]) -> Result<(), &'static str> {
        if !matches!(bytes.len(), 16) {
            return Err("`aes` expected exactly 16 bytes state.");
        }
        let nb = bytes.len() / 4;
        let nr = w.len() / nb - 1;
        if w.len() % nb != 0 {
            return Err("`aes` expanded key length supposed to be state length multiple.");
        } else if nr < 10 || 14 < nr {
            return Err("`aes` number of rounds derived from expanded key invalid.");
        }
        let mut state = bytes.chunks_exact(4).map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap())).collect::<Vec<u32>>();
        super::cipher(&mut state, w, nr, &super::SBOX, &super::MATRIX, &super::OFFSETS);
        for i in 0..state.len() {
            bytes[4 * i..4 * (i + 1)].copy_from_slice(&state[i].to_be_bytes());
        }
        Ok(())
    }
    
    pub fn decrypt_bytes(bytes: &mut [u8], w: &[u32]) -> Result<(), &'static str> {
        if bytes.len() != 16 {
            return Err("`aes` expected exactly 16 bytes state.");
        }
        let nb = bytes.len() / 4;
        let nr = w.len() / nb - 1;
        if w.len() % nb != 0 {
            return Err("`aes` expanded key length supposed to be state length multiple.");
        } else if nr < 10 || 14 < nr {
            return Err("`aes` number of rounds derived from expanded key invalid.");
        }
        let mut state = bytes.chunks_exact(4).map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap())).collect::<Vec<u32>>();
        super::inv_cipher(&mut state, w, nr, &super::INVSBOX, &super::INVMATRIX, &super::INVOFFSETS);
        for i in 0..state.len() {
            bytes[4 * i..4 * (i + 1)].copy_from_slice(&state[i].to_be_bytes());
        }
        Ok(())
    }
}


#[test]
fn test() {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let expected_cipher: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
    ];
    let w = key_expansion_bytes(&key, plaintext.len() / 4).unwrap();
    let mut block = plaintext;
    aes::encrypt_bytes(&mut block, &w).unwrap();
    assert_eq!(block, expected_cipher);
}

