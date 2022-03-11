fn pre_process(mut msg: Vec<u8>) -> Vec<u8> {
    let original_length_bits = (msg.len() * 8) as u64;

    // appending 1 (1000 0000)
    msg.push(128);

    // padding such as msg length is a multiple of 512
    let nb_zero_bits = 448u64
        .wrapping_sub(original_length_bits.wrapping_add(1u64))
        .wrapping_sub(7u64); // 7 bits are already in the "one" padding
    let nb_zero_bytes = nb_zero_bits / 8;

    for _ in 0..nb_zero_bytes {
        msg.push(0);
    }

    // padding original length as 64 bits
    let mut mask = 0xFF00000000000000;

    for i in 0..8 {
        let val64 = original_length_bits & mask;
        let val = (val64 >> (56 - (8 * i))) as u8;
        msg.push(val);
        mask >>= 8;
    }

    msg
}

fn parse_block<'a>(msg: &'a Vec<u8>, index: usize) -> Result<&'a [u8], &'static str> {
    let nb_blocks = msg.len() / 64;

    if index > nb_blocks {
        return Err("index is greater than the number of 512-bits blocks");
    }

    let start = ((512 * index) / 8) as usize;
    let end = ((start + 512) / 8) as usize;

    Ok(&msg[start..end])
}

fn init_hash() -> (Vec<u32>, Vec<u32>) {
    // first thirty-two bits of the fractional parts of the square roots of the first eight prime numbers
    // set by the SHA-256 specification
    let h_0 = vec![
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    //first thirty-two bits of the fractional parts of the cube roots of the first sixty-four prime numbers
    // set by the SHA-256 specification
    let k = vec![
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    (h_0, k)
}

fn sigma_2(x: u32) -> u32 {
    (x.rotate_right(7)) ^ (x.rotate_right(18)) ^ (x >> 3)
}

fn sigma_1(x: u32) -> u32 {
    (x.rotate_right(17)) ^ (x.rotate_right(19)) ^ (x >> 10)
}

fn message_schedule(chunk: &[u8]) -> Vec<u32> {
    // initializing the schedule with zeros
    let mut w: Vec<u32> = vec![0; 64];

    // copying the chunk into first 16 words of schedule message
    for i in 0..16 {
        let bytes_line = &chunk[4 * i..(4 * i) + 4];

        let mut word = 0u32;

        for j in 0..4 {
            word |= (bytes_line[j] as u32) << (24 - (8 * j));
        }

        w[i] = word;
    }

    // scheduling

    for i in 16..=63 {
        w[i] = sigma_1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(sigma_2(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    w
}

#[derive(Debug, PartialEq)]
struct WorkingVariables {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    f: u32,
    g: u32,
    h: u32,
}

impl WorkingVariables {
    fn iter(&self) -> Iter {
        Iter {
            inner: self,
            index: 0,
        }
    }
}

struct Iter<'a> {
    inner: &'a WorkingVariables,
    index: u8,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a u32;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.index {
            0 => &self.inner.a,
            1 => &self.inner.b,
            2 => &self.inner.c,
            3 => &self.inner.d,
            4 => &self.inner.e,
            5 => &self.inner.f,
            6 => &self.inner.g,
            7 => &self.inner.h,
            _ => return None,
        };
        self.index += 1;
        Some(ret)
    }
}

fn big_sigma_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn big_sigma_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn choice(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ (!e & g)
}

fn majority(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

fn compress_word(current: WorkingVariables, word: u32, k: u32) -> WorkingVariables {
    let s1 = big_sigma_1(current.e);
    let ch = choice(current.e, current.f, current.g);
    let temp1 = current
        .h
        .wrapping_add(s1)
        .wrapping_add(ch)
        .wrapping_add(k)
        .wrapping_add(word);

    let s0 = big_sigma_0(current.a);
    let maj = majority(current.a, current.b, current.c);
    let temp2 = s0.wrapping_add(maj);

    let h = current.g;
    let g = current.f;
    let f = current.e;
    let e = current.d.wrapping_add(temp1);
    let d = current.c;
    let c = current.b;
    let b = current.a;
    let a = temp1.wrapping_add(temp2);

    WorkingVariables {
        a,
        b,
        c,
        d,
        e,
        f,
        g,
        h,
    }
}

fn compress_chunk(
    init_working_var: WorkingVariables,
    schedule: Vec<u32>,
    k: &Vec<u32>,
) -> WorkingVariables {
    let mut current_working_var = init_working_var;

    for i in 0..64 {
        current_working_var = compress_word(current_working_var, schedule[i], k[i]);
    }

    current_working_var
}

fn add_compressed_chunk_in_hash(hash: Vec<u32>, compressed: WorkingVariables) -> Vec<u32> {
    let mut updated: Vec<u32> = Vec::new();

    for (index, var) in compressed.iter().enumerate() {
        updated.push(hash[index].wrapping_add(*var));
    }

    updated
}

fn append_hash_values(hash_values: Vec<u32>) -> String {
    hash_values
        .into_iter()
        .map(|h| format!("{:08x}", h))
        .collect::<String>()
}

fn sha_256(raw_msg: String) -> String {
    let msg = pre_process(raw_msg.as_bytes().to_vec());

    let (hash, k) = init_hash();
    let mut working_var = WorkingVariables {
        a: hash[0],
        b: hash[1],
        c: hash[2],
        d: hash[3],
        e: hash[4],
        f: hash[5],
        g: hash[6],
        h: hash[7],
    };

    let nb_blocks = msg.len() / 64;
    for i in 0..nb_blocks {
        let block = match parse_block(&msg, i) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let schedule = message_schedule(&block);

        working_var = compress_chunk(working_var, schedule, &k);
    }

    let updated_hash = add_compressed_chunk_in_hash(hash, working_var);

    append_hash_values(updated_hash)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn pre_processing() {
        let raw_msg = String::from("hi");

        let msg_bytes = raw_msg.as_bytes().to_vec();
        let msg = pre_process(msg_bytes);

        let pre_processed_bytes: Vec<u8> = vec![
            104, 105, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 16,
        ];

        assert_eq!(msg, pre_processed_bytes);
    }

    #[test]
    fn pre_processing_two_chunks() {
        let raw_msg = String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let msg_bytes = raw_msg.as_bytes().to_vec();

        let msg = pre_process(msg_bytes);

        let pre_processed_bytes: Vec<u8> = vec![
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 128, 0, 0, 0, 0, 0, 0, 1, 184,
        ];

        assert_eq!(msg, pre_processed_bytes);
    }

    #[test]
    fn parse_block_valid() {
        let raw_msg = String::from("hi");

        let msg_bytes = raw_msg.as_bytes().to_vec();
        let msg = pre_process(msg_bytes);

        let block = match parse_block(&msg, 0) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let valid_block: Vec<u8> = vec![
            104, 105, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 16,
        ];

        assert_eq!(block, valid_block);
    }

    #[test]
    #[should_panic(expected = "index is greater than the number of 512-bits blocks")]
    fn parse_block_invalid() {
        let raw_msg = String::from("hi");

        let msg_bytes = raw_msg.as_bytes().to_vec();
        let msg = pre_process(msg_bytes);

        let _block = match parse_block(&msg, 65) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };
    }

    #[test]
    fn hash_init() {
        let (h_0, k) = init_hash();

        let h_0_good = vec![
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let k_good = vec![
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        assert_eq!(h_0, h_0_good);
        assert_eq!(k, k_good);
    }

    #[test]
    fn sigma_2_test() {
        assert_eq!(sigma_2(0), 0);
        assert_eq!(sigma_2(1070767979), 1985952039);
    }

    #[test]
    fn sigma_1_test() {
        assert_eq!(sigma_1(0), 0);
        assert_eq!(sigma_1(2554764994), 2627669644);
    }

    #[test]
    fn big_sigma_0_test() {
        assert_eq!(big_sigma_0(1550818457), 228811051);
    }

    #[test]
    fn big_sigma_1_test() {
        assert_eq!(big_sigma_1(2184641807), 2223381226);
    }

    #[test]
    fn choice_test() {
        let ch = choice(2184641807, 1443935371, 1754755858);
        assert_eq!(ch, 1787934235);
    }

    #[test]
    fn majority_test() {
        let maj = majority(1550818457, 2150493220, 3784171943);
        assert_eq!(maj, 3224235173);
    }

    #[test]
    fn message_scheduling() {
        let raw_msg = String::from("hi");

        let msg_bytes = raw_msg.as_bytes().to_vec();
        let msg = pre_process(msg_bytes);

        let block = match parse_block(&msg, 0) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let schedule = message_schedule(&block);

        let good_schedule = vec![
            1751744512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 1751744512, 655360,
            4028244825, 1073742468, 1442562182, 16951296, 2554764994, 1768538123, 2628325004,
            3359156034, 3870358022, 2641818552, 1669114800, 1070767979, 1243915016, 652088426,
            1989877954, 3567380066, 2182544060, 1769595360, 3793356024, 1233562599, 1845350614,
            2846974476, 2029867211, 391648972, 822598888, 3482373360, 961015826, 1589172728,
            1332217501, 1505673201, 942134798, 1705278904, 418803759, 3236787579, 2755738675,
            2187538558, 3596201111, 2915422290, 1644498225, 2748313998, 3832314439, 1510965048,
            991015767, 3092557612, 863408739, 1830348433,
        ];

        assert_eq!(schedule, good_schedule);
    }

    #[test]
    fn compress_word_test() {
        let raw_msg = String::from("hi");

        let msg_bytes = raw_msg.as_bytes().to_vec();
        let msg = pre_process(msg_bytes);

        let block = match parse_block(&msg, 0) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let schedule = message_schedule(&block);

        let (current, k) = init_hash();

        let current_working_var = WorkingVariables {
            a: current[0],
            b: current[1],
            c: current[2],
            d: current[3],
            e: current[4],
            f: current[5],
            g: current[6],
            h: current[7],
        };

        let compressed = compress_word(current_working_var, schedule[0], k[0]);

        let compressed_good = WorkingVariables {
            a: 1685194829,
            b: 1779033703,
            c: 3144134277,
            d: 1013904242,
            e: 20013730,
            f: 1359893119,
            g: 2600822924,
            h: 528734635,
        };

        assert_eq!(compressed, compressed_good);
    }

    #[test]
    fn compress_chunk_test() {
        let raw_msg = String::from("hi");

        let msg_bytes = raw_msg.as_bytes().to_vec();
        let msg = pre_process(msg_bytes);

        let block = match parse_block(&msg, 0) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let schedule = message_schedule(&block);

        let (hash, k) = init_hash();

        let init_working_var = WorkingVariables {
            a: hash[0],
            b: hash[1],
            c: hash[2],
            d: hash[3],
            e: hash[4],
            f: hash[5],
            g: hash[6],
            h: hash[7],
        };

        let compressed = compress_chunk(init_working_var, schedule, &k);

        let compressed_good = WorkingVariables {
            a: 624516319,
            b: 2837953809,
            c: 2736450103,
            d: 1551180337,
            e: 3214443962,
            f: 3336033166,
            g: 2835841031,
            h: 2152836491,
        };

        assert_eq!(compressed, compressed_good);
    }

    #[test]
    fn add_compressed_chunk_in_hash_test() {
        let (hash, k) = init_hash();

        let raw_msg = String::from("hi");

        let msg_bytes = raw_msg.as_bytes().to_vec();
        let msg = pre_process(msg_bytes);

        let block = match parse_block(&msg, 0) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let schedule = message_schedule(&block);

        let init_working_var = WorkingVariables {
            a: hash[0],
            b: hash[1],
            c: hash[2],
            d: hash[3],
            e: hash[4],
            f: hash[5],
            g: hash[6],
            h: hash[7],
        };

        let compressed = compress_chunk(init_working_var, schedule, &k);

        let updated_hash = add_compressed_chunk_in_hash(hash, compressed);

        let updated = vec![
            0x8f434346, 0x648f6b96, 0xdf89dda9, 0x01c5176b, 0x10a6d839, 0x61dd3c1a, 0xc88b59b2,
            0xdc327aa4,
        ];

        assert_eq!(updated_hash, updated);
    }

    #[test]
    fn append_hash_values_test() {
        let updated_hash = vec![
            0x8f434346, 0x648f6b96, 0xdf89dda9, 0x01c5176b, 0x10a6d839, 0x61dd3c1a, 0xc88b59b2,
            0xdc327aa4,
        ];

        let hash = append_hash_values(updated_hash);

        let hash_good =
            String::from("8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4");

        assert_eq!(hash, hash_good);
    }

    #[test]
    fn sha_256_empty_string() {
        let msg = String::from("");

        let hash = sha_256(msg);
        let hash_good = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        assert_eq!(hash, hash_good);
    }

    #[test]
    fn sha_256_one_chunk() {
        let msg = String::from("hi");

        let hash = sha_256(msg);
        let hash_good = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4";

        assert_eq!(hash, hash_good);
    }
}
