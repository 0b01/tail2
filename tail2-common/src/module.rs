use gimli::BaseAddresses;

#[derive(Copy, Clone)]
pub struct Module {
    /// 512 kb
    pub eh_frame_data: [u8; 512 << 10], 
    pub eh_frame_len: usize,
    // addr: BaseAddresses,
    // idx: DwarfCfiIndex,
}

#[cfg(feature="user")]
unsafe impl aya::Pod for Module {}