pub fn sigma_0(x: u32) -> u32 {
    (x.rotate_right(7)) ^ (x.rotate_right(18)) ^ (x >> 3)
}

pub fn sigma_1(x: u32) -> u32 {
    (x.rotate_right(17)) ^ (x.rotate_right(19)) ^ (x >> 10)
}

pub fn big_sigma_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

pub fn big_sigma_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

pub fn choice(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ (!e & g)
}

pub fn majority(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigma_0_test() {
        assert_eq!(sigma_0(0), 0);
        assert_eq!(sigma_0(0x3fd29f6b), 0x765f3927);
    }

    #[test]
    fn sigma_1_test() {
        assert_eq!(sigma_1(0), 0);
        assert_eq!(sigma_1(0x98469ec2), 0x9c9f0e8c);
    }

    #[test]
    fn big_sigma_0_test() {
        assert_eq!(big_sigma_0(0x5c6f9c99), 0xda3612b);
    }

    #[test]
    fn big_sigma_1_test() {
        assert_eq!(big_sigma_1(0x8236fd0f), 0x84861aea);
    }

    #[test]
    fn choice_test() {
        let ch = choice(0x8236fd0f, 0x5610b48b, 0x68977312);
        assert_eq!(ch, 0x6a91b61b);
    }

    #[test]
    fn majority_test() {
        let maj = majority(0x5c6f9c99, 0x802dec24, 0xe18de1a7);
        assert_eq!(maj, 0xc02deca5);
    }
}
