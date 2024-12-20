// first thirty-two bits of the fractional parts of the square roots of the first eight prime numbers
// set by the SHA-256 specification
pub const H_0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

//first thirty-two bits of the fractional parts of the cube roots of the first sixty-four prime numbers
// set by the SHA-256 specification
pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

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
