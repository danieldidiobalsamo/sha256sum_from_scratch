mod math;

mod working_variables;
use working_variables::WorkingVariables;

fn pre_process(mut msg: Vec<u8>) -> Vec<u8> {
    let original_length_bits = (msg.len() * 8) as u64;

    // appending 1 (1000 0000)
    msg.push(128);

    // padding with zeros such as msg length is a multiple of 512
    let nb_zero_bits = (512 + 448 - ((original_length_bits as u32) % 512 + 1)) % 512;
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
    let end = (start + (512 / 8)) as usize;

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

fn message_schedule(chunk: &[u8]) -> Vec<u32> {
    // initializing the schedule with zeros
    let mut w: Vec<u32> = vec![0; 64];

    // copying the chunk into first 16 words of message schedule
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
        w[i] = math::sigma_0(w[i - 15])
            .wrapping_add(w[i - 7])
            .wrapping_add(math::sigma_1(w[i - 2]))
            .wrapping_add(w[i - 16]);
    }

    w
}

fn compress_word(current: WorkingVariables, word: u32, k: u32) -> WorkingVariables {
    let s1 = math::big_sigma_1(current.e);
    let ch = math::choice(current.e, current.f, current.g);
    let temp1 = current
        .h
        .wrapping_add(s1)
        .wrapping_add(ch)
        .wrapping_add(k)
        .wrapping_add(word);

    let s0 = math::big_sigma_0(current.a);
    let maj = math::majority(current.a, current.b, current.c);
    let temp2 = s0.wrapping_add(maj);

    let h = current.g;
    let g = current.f;
    let f = current.e;
    let e = current.d.wrapping_add(temp1);
    let d = current.c;
    let c = current.b;
    let b = current.a;
    let a = temp1.wrapping_add(temp2);

    WorkingVariables::new(&[a, b, c, d, e, f, g, h])
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

fn add_compressed_chunk_in_hash(hash: Vec<u32>, compressed: &WorkingVariables) -> Vec<u32> {
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

fn compress_msg(
    msg: Vec<u8>,
    init_working_var: WorkingVariables,
    k: Vec<u32>,
    init_hash: Vec<u32>,
) -> Vec<u32> {
    let mut hash = init_hash;
    let mut working_var = init_working_var;

    let nb_blocks = msg.len() / 64;
    for i in 0..nb_blocks {
        working_var.update(&hash);

        let block = match parse_block(&msg, i) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let schedule = message_schedule(&block);

        working_var = compress_chunk(working_var, schedule, &k);

        hash = add_compressed_chunk_in_hash(hash, &working_var);
    }

    hash
}

pub fn sha_256(raw_msg: Vec<u8>) -> String {
    let msg = pre_process(raw_msg);

    let (hash, k) = init_hash();
    let init_working_var = WorkingVariables::new(&hash);

    let updated_hash = compress_msg(msg, init_working_var, k, hash);

    append_hash_values(updated_hash)
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::fs;

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
    fn pre_processing_long_one() {
        let raw_msg = String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let msg_bytes = raw_msg.as_bytes().to_vec();

        let msg = pre_process(msg_bytes);

        let pre_processed_bytes: Vec<u8> = vec![
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 128, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 88,
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
    fn parse_block_whole_message() {
        let raw_msg = String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let msg_bytes = raw_msg.as_bytes().to_vec();
        let msg = pre_process(msg_bytes);

        let block0 = match parse_block(&msg, 0) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let good_block0 = vec![
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
        ];

        assert_eq!(block0, good_block0);

        let block1 = match parse_block(&msg, 1) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let good_block1 = vec![
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 88,
        ];

        assert_eq!(block1, good_block1);
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
    fn message_scheduling() {
        let raw_msg = String::from("hi");

        let msg_bytes = raw_msg.as_bytes().to_vec();
        let msg = pre_process(msg_bytes);

        let block = match parse_block(&msg, 0) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let schedule = message_schedule(&block);

        let good_schedule: Vec<u32> = vec![
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
    fn message_scheduling_long_one() {
        let raw_msg = String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let msg_bytes = raw_msg.as_bytes().to_vec();
        let msg = pre_process(msg_bytes);

        let block = match parse_block(&msg, 0) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let schedule = message_schedule(&block);

        let good_schedule: Vec<u32> = vec![
            1633771873, 1633771873, 1633771873, 1633771873, 1633771873, 1633771873, 1633771873,
            1633771873, 1633771873, 1633771873, 1633771873, 1633771873, 1633771873, 1633771873,
            1633771873, 1633771873, 4127079996, 4127079996, 845026631, 845026631, 562127449,
            562127449, 4142485024, 2340825851, 2097165901, 4202070679, 1214676619, 2864781893,
            169889552, 2638362293, 2986790745, 619170806, 2545628807, 1752194553, 3897866632,
            1354584167, 2037939211, 3798754737, 3125072781, 2053181897, 1764381550, 231544716,
            3582021090, 2147669598, 1900325583, 2688439274, 112371858, 1110188099, 2407788112,
            4108513933, 2210941747, 4027291822, 2910535786, 3783077996, 2655981588, 2366978167,
            612225234, 1494184812, 815738812, 1069923231, 447001511, 943759201, 3929715958,
            242742810,
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

        let current_working_var = WorkingVariables::new(&current);

        let compressed = compress_word(current_working_var, schedule[0], k[0]);

        let compressed_good = WorkingVariables::new(&[
            0x6472084d, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0x13162a2, 0x510e527f, 0x9b05688c,
            0x1f83d9ab,
        ]);

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

        let init_working_var = WorkingVariables::new(&hash);
        let compressed = compress_chunk(init_working_var, schedule, &k);

        let compressed_good = WorkingVariables::new(&[
            0x25395cdf, 0xa927bd11, 0xa31aea37, 0x5c752231, 0xbf9885ba, 0xc6d7d38e, 0xa9078007,
            0x8051ad8b,
        ]);

        assert_eq!(compressed, compressed_good);
    }

    #[test]
    fn compress_msg_test() {
        let raw_msg = String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let msg_bytes = raw_msg.as_bytes().to_vec();

        let msg = pre_process(msg_bytes);

        let (hash, k) = init_hash();

        let init_working_var = WorkingVariables::new(&hash);

        let updated_hash = compress_msg(msg, init_working_var, k, hash);

        let updated_hash_good = vec![
            0x3e24531c, 0xdaa595ab, 0x56f976b9, 0x6c1a1df8, 0x009eabec, 0x300a5a02, 0x61c0e44f,
            0x47a43b89,
        ];

        assert_eq!(updated_hash, updated_hash_good);
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

        let init_working_var = WorkingVariables::new(&hash);

        let compressed = compress_chunk(init_working_var, schedule, &k);

        let updated_hash = add_compressed_chunk_in_hash(hash, &compressed);

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
        let msg = String::from("").as_bytes().to_vec();

        let hash = sha_256(msg);
        let hash_good = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        assert_eq!(hash, hash_good);
    }

    #[test]
    fn sha_256_one_chunk() {
        let msg = String::from("hi").as_bytes().to_vec();

        let hash = sha_256(msg);
        let hash_good = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4";

        assert_eq!(hash, hash_good);
    }

    #[test]
    fn sha_256_long_one() {
        let msg = String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").as_bytes().to_vec();

        let hash = sha_256(msg);
        let hash_good = "3e24531cdaa595ab56f976b96c1a1df8009eabec300a5a0261c0e44f47a43b89";

        assert_eq!(hash, hash_good);
    }

    #[test]
    fn sha_256_file() {
        let msg = fs::read("./sample_files_for_testing/sample").unwrap();

        let hash = sha_256(msg);
        let hash_good = "a5cac392386ce08fc3ce1a089c912a0f2d7de925a8f5617367c9822ee9b28f37";

        assert_eq!(hash, hash_good);
    }

    #[test]
    fn sha_256_binary_file() {
        let msg = fs::read("./sample_files_for_testing/sample.pdf").unwrap();

        let hash = sha_256(msg);
        let hash_good = "f7134fdeda6eece3a3508096f3a64a123a397d530753e426ce9a9838dbae0f99";

        assert_eq!(hash, hash_good);
    }
}
