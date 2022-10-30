use gimli::BaseAddresses;

#[derive(Copy, Clone, Debug)]
pub struct Module {
    /// 512 kb
    pub eh_frame_data: [u8; 512 << 10], 
    pub eh_frame_len: usize,
    // addr: BaseAddresses,
    // idx: DwarfCfiIndex,
}

impl Default for Module {
    fn default() -> Self {
        Self {
            eh_frame_data: [0; 512 << 10],
            eh_frame_len: Default::default()
        }
    }
}

#[cfg(feature="user")]
impl Module {
    pub fn from_path(p: &std::path::PathBuf) -> Result<Self, anyhow::Error> {
        use anyhow::Context;
        use object::{Object, ObjectSection};
        let file = std::fs::File::open(&p)?;

        let mmap = unsafe { memmap2::MmapOptions::new().map(&file).unwrap() };
        let file = object::File::parse(&mmap[..]).unwrap();

        let text = file.section_by_name(".text");
        let eh_frame = file.section_by_name(".eh_frame");
        let got = file.section_by_name(".got");
        let eh_frame_hdr = file.section_by_name(".eh_frame_hdr");

        // let bases = BaseAddresses::default()
        //     .set_eh_frame(eh_frame.as_ref().unwrap().address())
        //     .set_eh_frame_hdr(eh_frame_hdr.as_ref().unwrap().address())
        //     .set_text(text.as_ref().unwrap().address())
        //     .set_got(got.as_ref().unwrap().address());

        let eh_frame_data = eh_frame.as_ref().unwrap().data().unwrap();
        // let eh_frame = gimli::EhFrame::from(gimli::EndianSlice::new(eh_frame_data, LittleEndian));
        // let idx = DwarfCfiIndex::try_new(eh_frame, bases.clone(), 0).unwrap();
        // (eh_frame_data.to_owned(), bases, idx)
        let mut ret = Self::default();
        ret.eh_frame_len = eh_frame_data.len();
        if eh_frame_data.len() > 512 << 10 {
            None.context("too big...")?;
        }
        ret.eh_frame_data[..ret.eh_frame_len].copy_from_slice(&eh_frame_data);
        Ok(ret)
    }
}

#[cfg(feature="user")]
unsafe impl aya::Pod for Module {}