fn pre_process(mut msg: Vec<u8>) -> Vec<u8> {
    let original_length_bits = msg.len() * 8;

    // appending 1 (1000 0000)
    msg.push(128);

    // padding such as msg length is a multiple of 512
    let nb_zero_bits = 448 - (original_length_bits + 1) - 7; // 7 bits are already in the "one" padding
    let nb_zero_bytes = nb_zero_bits / 8;

    for _ in 0..nb_zero_bytes {
        msg.push(0);
    }

    // padding original length as 64 bits
    let mut mask = 0xFF00000000000000;

    for _ in 0..8 {
        let val = (original_length_bits & mask) as u8;
        msg.push(val);
        mask = mask >> 8;
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
        let mut bytes_line = [0u8; 4];
        bytes_line.clone_from_slice(&chunk[4 * i..(4 * i) + 4]);

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
}
