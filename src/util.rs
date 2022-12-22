pub fn bytes_to_word(data: &[u8]) -> u32 {
    u32::from_le_bytes(data.try_into().unwrap())
}

#[test]
fn test_bytes_to_word() {
    bytes_to_word(&[1, 2, 3, 4]);
}

pub fn word_to_bytes(data: u32) -> [u8; 4] {
    data.to_le_bytes()
}

pub fn msb(n: u32) -> usize {
    for i in (0..32).rev() {
        if (1 << i) & n != 0 {
            return i;
        }
    }
    return 0;
}

#[test]
fn test_msb() {
    assert_eq!(msb(0b1100110), 6);
}
