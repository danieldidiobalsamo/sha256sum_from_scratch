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

    msg.append(&mut vec![0; nb_zero_bytes as usize]);

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

fn parse_block(msg: &[u8], index: usize) -> Result<&[u8], &'static str> {
    if index > msg.len() / 64 {
        return Err("index is greater than the number of 512-bits blocks");
    }

    let start = (512 * index) / 8;
    let end = start + (512 / 8);

    Ok(&msg[start..end])
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
    k: &[u32],
) -> WorkingVariables {
    let mut current_working_var = init_working_var;

    for i in 0..64 {
        current_working_var = compress_word(current_working_var, schedule[i], k[i]);
    }

    current_working_var
}

fn add_compressed_chunk_in_hash(hash: &[u32], compressed: &WorkingVariables) -> Vec<u32> {
    let mut updated: Vec<u32> = Vec::new();

    for (index, var) in compressed.iter().enumerate() {
        updated.push(hash[index].wrapping_add(*var));
    }

    updated
}

fn append_hash_values(hash_values: Vec<u32>) -> String {
    hash_values
        .into_iter()
        .fold(String::new(), |full_hash, hash| {
            format!("{}{:08x}", full_hash, hash)
        })
}

fn compress_msg(
    msg: Vec<u8>,
    init_working_var: WorkingVariables,
    k: &[u32],
    init_hash: &[u32],
) -> Vec<u32> {
    let mut hash = init_hash.to_vec();
    let mut working_var = init_working_var;

    for i in 0..msg.len() / 64 {
        working_var.update(&hash);

        let block = match parse_block(&msg, i) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        let schedule = message_schedule(block);

        working_var = compress_chunk(working_var, schedule, &k);

        hash = add_compressed_chunk_in_hash(&hash, &working_var);
    }

    hash.to_vec()
}

pub fn sha_256(raw_msg: Vec<u8>) -> String {
    let msg = pre_process(raw_msg);

    let (hash, k) = (math::H_0, math::K);
    let init_working_var = WorkingVariables::new(&hash);

    let updated_hash = compress_msg(msg, init_working_var, &k, &hash);

    append_hash_values(updated_hash)
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::fs;

    ////////////////// functions for setting up unit tests scenarios
    fn get_short_msg() -> String {
        String::from("hi")
    }

    fn get_long_msg() -> String {
        String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    }

    fn get_short_pre_processed() -> Vec<u8> {
        let raw_msg = get_short_msg();
        let msg_bytes = raw_msg.as_bytes().to_vec();

        pre_process(msg_bytes)
    }

    fn get_long_pre_processed() -> Vec<u8> {
        let raw_msg = get_long_msg();
        let msg_bytes = raw_msg.as_bytes().to_vec();

        pre_process(msg_bytes)
    }

    fn get_first_block_short() -> Vec<u8> {
        let msg = get_short_pre_processed();

        let block = match parse_block(&msg, 0) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        block.to_vec()
    }

    fn get_first_block_long() -> Vec<u8> {
        let msg = get_long_pre_processed();

        let block = match parse_block(&msg, 0) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };

        block.to_vec()
    }

    fn get_schedule_short() -> Vec<u32> {
        let block = get_first_block_short();

        message_schedule(&block)
    }

    fn get_compressed_msg_short() -> WorkingVariables {
        let schedule = get_schedule_short();
        let (hash, k) = (math::H_0, math::K);

        let init_working_var = WorkingVariables::new(&hash);

        compress_chunk(init_working_var, schedule, &k)
    }

    ////////////////// unit tests
    #[test]
    fn pre_processing() {
        let raw_msg = get_short_msg(); // setting up this scenario

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
    fn pre_processing_long_one() {
        let raw_msg = get_long_msg(); // setting up this scenario

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
        let msg = get_short_pre_processed(); // setting up this scenario

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
        let msg = get_short_pre_processed(); // setting up this scenario

        let _block = match parse_block(&msg, 65) {
            Ok(block) => block,
            Err(err) => panic!("{err}"),
        };
    }

    #[test]
    fn parse_block_long_one_whole_message() {
        let msg = get_long_pre_processed(); // setting up this scenario

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
    fn message_schedule_test_short() {
        let block = get_first_block_short(); // setting up this scenario

        let schedule = message_schedule(&block);

        let good_schedule: Vec<u32> = vec![
            0x68698000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10,
            0x68698000, 0xa0000, 0xf01a2359, 0x40000284, 0x55fbc086, 0x102a800, 0x98469ec2,
            0x6969c00b, 0x9ca90e8c, 0xc838a742, 0xe6b0fa06, 0x9d76f3b8, 0x637cabb0, 0x3fd29f6b,
            0x4a24a308, 0x26de146a, 0x769b20c2, 0xd4a1e662, 0x8216fabc, 0x6979e1e0, 0xe21a04f8,
            0x4986abe7, 0x6dfdd0d6, 0xa9b1620c, 0x78fd50cb, 0x175816cc, 0x3107dce8, 0xcf90ccf0,
            0x3947f012, 0x5eb8d9f8, 0x4f68069d, 0x59bebff1, 0x3827d60e, 0x65a47db8, 0x18f6702f,
            0xc0ed757b, 0xa4413c33, 0x8263307e, 0xd659ac97, 0xadc5d052, 0x62050d31, 0xa3cff18e,
            0xe46c7a47, 0x5a0f7f38, 0x3b11b357, 0xb854af2c, 0x33769263, 0x6d18e691,
        ];

        assert_eq!(schedule, good_schedule);
    }

    #[test]
    fn message_scheduling_long_one() {
        let block = get_first_block_long(); // setting up this scenario

        let schedule = message_schedule(&block);

        let good_schedule: Vec<u32> = vec![
            0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
            0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
            0x61616161, 0x61616161, 0xf5fe3e3c, 0xf5fe3e3c, 0x325e1547, 0x325e1547, 0x21816259,
            0x21816259, 0xf6e94e20, 0x8b862afb, 0x7d00364d, 0xfa768297, 0x48667e8b, 0xaac11a45,
            0xa204f10, 0x9d4236b5, 0xb206cf59, 0x24e7cbf6, 0x97bb3687, 0x68705df9, 0xe854b988,
            0x50bd5067, 0x79787c0b, 0xe26c65b1, 0xba44d38d, 0x7a6111c9, 0x692a536e, 0xdcd178c,
            0xd5814de2, 0x8002d65e, 0x7144aacf, 0xa03e53ea, 0x6b2a892, 0x422c2043, 0x8f83ee50,
            0xf4e2f28d, 0x83c84b33, 0xf00b98ae, 0xad7b406a, 0xe17d306c, 0x9e4f1014, 0x8d153877,
            0x247dd0d2, 0x590f736c, 0x309f2fbc, 0x3fc5bb9f, 0x1aa4b3a7, 0x38409f61, 0xea3ab4f6,
            0xe77f61a,
        ];

        assert_eq!(schedule, good_schedule);
    }

    #[test]
    fn compress_word_test() {
        let schedule = get_schedule_short(); // setting up this scenario

        let (current, k) = (math::H_0, math::K);
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
        let schedule = get_schedule_short(); // setting up this scenario

        let (hash, k) = (math::H_0, math::K);

        let init_working_var = WorkingVariables::new(&hash);
        let compressed = compress_chunk(init_working_var, schedule, &k);

        let compressed_good = WorkingVariables::new(&[
            0x25395cdf, 0xa927bd11, 0xa31aea37, 0x5c752231, 0xbf9885ba, 0xc6d7d38e, 0xa9078007,
            0x8051ad8b,
        ]);

        assert_eq!(compressed, compressed_good);
    }

    #[test]
    fn compress_msg_long() {
        let msg = get_long_pre_processed(); // setting up this scenario

        let (hash, k) = (math::H_0, math::K);

        let init_working_var = WorkingVariables::new(&hash);

        let updated_hash = compress_msg(msg, init_working_var, &k, &hash);

        let updated_hash_good = vec![
            0x3e24531c, 0xdaa595ab, 0x56f976b9, 0x6c1a1df8, 0x009eabec, 0x300a5a02, 0x61c0e44f,
            0x47a43b89,
        ];

        assert_eq!(updated_hash, updated_hash_good);
    }

    #[test]
    fn add_compressed_chunk_in_hash_test() {
        let (hash, _) = (math::H_0, math::K);
        let compressed = get_compressed_msg_short(); // setting up this scenario

        let updated_hash = add_compressed_chunk_in_hash(&hash, &compressed);

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
        let msg = get_long_msg().as_bytes().to_vec();

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
