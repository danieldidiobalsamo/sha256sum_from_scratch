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
        assert_eq!(sigma_0(1070767979), 1985952039);
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
}
