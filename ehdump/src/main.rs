use framehop::{dwarf::{DwarfUnwinder, UnwindSectionType, DwarfCfiIndex}, FrameAddress};
use gimli::{read::*, LittleEndian, EhFrameOffset};
use object::{Object, ObjectSection};
use std::{
    path::{Path, PathBuf}, str::EncodeUtf16,
};

fn open_file_with_fallback(
    path: &Path,
    extra_dir: Option<&Path>,
) -> std::io::Result<std::fs::File> {
    match (std::fs::File::open(path), extra_dir, path.file_name()) {
        (Err(_), Some(extra_dir), Some(filename)) => {
            let p: PathBuf = [extra_dir, Path::new(filename)].iter().collect();
            std::fs::File::open(&p)
        }
        (result, _, _) => result,
    }
}

fn load_eh(path: &str) -> (Vec<u8>, BaseAddresses, DwarfCfiIndex) {
    let objpath = Path::new(path);
    let file = open_file_with_fallback(&objpath, None).unwrap();
    let mmap = unsafe { memmap2::MmapOptions::new().map(&file).unwrap() };
    let file = object::File::parse(&mmap[..]).unwrap();

    let text = file.section_by_name(".text");
    let eh_frame = file.section_by_name(".eh_frame");
    let got = file.section_by_name(".got");
    let eh_frame_hdr = file.section_by_name(".eh_frame_hdr");

    let bases = BaseAddresses::default()
        .set_eh_frame(eh_frame.as_ref().unwrap().address())
        .set_eh_frame_hdr(eh_frame_hdr.as_ref().unwrap().address())
        .set_text(text.as_ref().unwrap().address())
        .set_got(got.as_ref().unwrap().address());

    let eh_frame_data = eh_frame.as_ref().unwrap().data().unwrap();
    let eh_frame = EhFrame::from(EndianSlice::new(eh_frame_data, LittleEndian));
    let idx = DwarfCfiIndex::try_new(eh_frame, bases.clone(), 0).unwrap();
    dbg!(eh_frame_data.len());
    (eh_frame_data.to_owned(), bases, idx)
}

type Mod = (Vec<u8>, BaseAddresses, DwarfCfiIndex);

fn main() {
    // let's allocate 500 kb for each eh_frame because why not
    let mut maps = Vec::<(u64, u64, Mod)>::new();
    maps.push((
        0xaaaad87d0000,
        0xaaaad87d1000,
        load_eh("/home/g/tail2/testapp/malloc/a.out"),
    ));
    maps.push((
        0xffffb7030000,
        0xffffb71b9000,
        load_eh("/usr/lib/aarch64-linux-gnu/libc.so.6"),
    ));
    // let mut eh_frame = EhFrame::from(EndianSlice::new(eh_frame_data.as_slice(), LittleEndian));
    // eh_frame.set_address_size(8);
    let pc: u64 = 0xFFFFB70BD640;
    let sp: u64 = 281474587663616;
    let fp: u64 = 281474587663616;
    let lr: u64 = 187650753234920;
    let find_module_from_addr = |addr| -> Option<(u64, &Mod)> {
        for (a,b, c) in &maps {
            if a <= addr && addr < b {
                return Some((*a, c));
            }
        }
        None
    };
    let (a, (data, bases, idx)) = find_module_from_addr(&pc).unwrap();

    let rel_lookup_address = (pc - a) as u32;
    println!("{:x}", rel_lookup_address);
    let fde_offset = idx.fde_offset_for_relative_address(rel_lookup_address);
    let lookup_svma = rel_lookup_address as u64;
    let mut ctx = Box::new(UnwindContext::new());
    let unwind_info = {
        let mut eh_frame = EhFrame::from(EndianSlice::new(data.as_slice(), LittleEndian));
        eh_frame.set_address_size(8);
        let fde = eh_frame.fde_from_offset(
            &bases,
            EhFrameOffset::from(fde_offset.unwrap() as usize),
            EhFrame::cie_from_offset,
        ).unwrap();
        // let fde = fde.map_err(DwarfUnwinderError::FdeFromOffsetFailed)?;
        let unwind_info = fde
            .unwind_info_for_address(
                &eh_frame,
                &bases,
                &mut ctx,
                lookup_svma,
            ).unwrap();
            // .map_err(DwarfUnwinderError::UnwindInfoForAddressFailed)?;
        unwind_info
    };
    // dbg!(unwind_info);
    // A::unwind_frame::<F, R, S>(unwind_info, encoding, regs, is_first_frame, read_stack)
}