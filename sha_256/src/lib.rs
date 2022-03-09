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
}
