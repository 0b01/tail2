use std::{
    ops::Range,
    path::{Path, PathBuf}, os::unix::prelude::OsStrExt,
};

use ::debugid::{CodeId, DebugId};
use framehop::{Module, ModuleSvmaInfo, ModuleUnwindData, TextByteData, Unwinder, aarch64::{UnwindRegsAarch64, UnwinderAarch64, CacheAarch64}};
use fxhash::{FxHashSet, FxHashMap};
use log::error;
use object::{Object, ObjectSection, ObjectSegment, SectionKind};
use procfs::process::{MemoryMap, MMapPath};
use tail2_common::Stack;
use crate::{unwinding::{debugid::debug_id_for_object}};

use self::debugid::DebugIdExt;

pub mod debugid;

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

fn compute_image_bias<'data: 'file, 'file>(
    file: &'file impl Object<'data, 'file>,
    mapping_start_file_offset: u64,
    mapping_start_avma: u64,
    mapping_size: u64,
) -> Option<u64> {
    let mapping_end_file_offset = mapping_start_file_offset + mapping_size;

    // Find one of the text sections in this mapping, to map file offsets to SVMAs.
    // It would make more sense look for to ELF LOAD commands (which the `object`
    // crate exposes as segments), but this does not work for the synthetic .so files
    // created by `perf inject --jit` - those don't have LOAD commands.
    let (section_start_file_offset, section_start_svma) = match file
        .sections()
        .filter(|s| s.kind() == SectionKind::Text)
        .find_map(|s| match s.file_range() {
            Some((section_start_file_offset, section_size)) => {
                let section_end_file_offset = section_start_file_offset + section_size;
                if mapping_start_file_offset <= section_start_file_offset
                    && section_end_file_offset <= mapping_end_file_offset
                {
                    Some((section_start_file_offset, s.address()))
                } else {
                    None
                }
            }
            _ => None,
        }) {
        Some(section_info) => section_info,
        None => {
            println!(
                "Could not find section covering file offset range 0x{:x}..0x{:x}",
                mapping_start_file_offset, mapping_end_file_offset
            );
            return None;
        }
    };

    let section_start_avma =
        mapping_start_avma + (section_start_file_offset - mapping_start_file_offset);

    // Compute the offset between AVMAs and SVMAs. This is the bias of the image.
    Some(section_start_avma - section_start_svma)
}

/// Tell the unwinder about this module
///
/// The unwinder needs to know about it in case we need to do DWARF stack
/// unwinding - it needs to get the unwinding information from the binary.
/// The profile needs to know about this module so that it can assign
/// addresses in the stack to the right module and so that symbolication
/// knows where to get symbols for this module.
pub fn add_module_to_unwinder<U>(
    unwinder: &mut U,
    path_slice: &[u8],
    mapping_start_file_offset: u64,
    mapping_start_avma: u64,
    mapping_size: u64,
    build_id: Option<&[u8]>,
    extra_binary_artifact_dir: Option<&Path>,
) -> Option<()>
where
    U: Unwinder<Module = Module<Vec<u8>>>,
{
    let path = std::str::from_utf8(path_slice).unwrap();
    let objpath = Path::new(path);

    let file = open_file_with_fallback(objpath, extra_binary_artifact_dir).ok();
    if file.is_none() && !path.starts_with('[') {
        // eprintln!("Could not open file {:#?}", objpath);
    }

    let mapping_end_avma = mapping_start_avma + mapping_size;
    let avma_range = mapping_start_avma..mapping_end_avma;

    let code_id;
    let debug_id;
    let base_avma;

    if let Some(file) = file {
        let mmap = match unsafe { memmap2::MmapOptions::new().map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                eprintln!("Could not mmap file {}: {:#?}", path, err);
                return None;
            }
        };

        fn section_data<'a>(section: &impl ObjectSection<'a>) -> Option<Vec<u8>> {
            section.data().ok().map(|data| data.to_owned())
        }

        let file = match object::File::parse(&mmap[..]) {
            Ok(file) => file,
            Err(_) => {
                eprintln!("File {:#?} has unrecognized format", objpath);
                return None;
            }
        };

        // Verify build ID.
        if let Some(build_id) = build_id {
            match file.build_id().ok().flatten() {
                Some(file_build_id) if build_id == file_build_id => {
                    // Build IDs match. Good.
                }
                Some(file_build_id) => {
                    let file_build_id = CodeId::from_binary(file_build_id);
                    let expected_build_id = CodeId::from_binary(build_id);
                    eprintln!(
                        "File {:#?} has non-matching build ID {} (expected {})",
                        objpath, file_build_id, expected_build_id
                    );
                    return None;
                }
                None => {
                    eprintln!(
                        "File {:#?} does not contain a build ID, but we expected it to have one",
                        objpath
                    );
                    return None;
                }
            }
        }

        // Compute the AVMA that maps to SVMA zero. This is also called the "bias" of the
        // image. On ELF it is also the image load address.
        let base_svma = 0;
        base_avma = compute_image_bias(
            &file,
            mapping_start_file_offset,
            mapping_start_avma,
            mapping_size,
        )?;

        let text = file.section_by_name(".text");
        let text_env = file.section_by_name("text_env");
        let eh_frame = file.section_by_name(".eh_frame");
        let got = file.section_by_name(".got");
        let eh_frame_hdr = file.section_by_name(".eh_frame_hdr");

        let unwind_data = match (
            eh_frame.as_ref().and_then(section_data),
            eh_frame_hdr.as_ref().and_then(section_data),
        ) {
            (Some(eh_frame), Some(eh_frame_hdr)) => {
                ModuleUnwindData::EhFrameHdrAndEhFrame(eh_frame_hdr, eh_frame)
            }
            (Some(eh_frame), None) => ModuleUnwindData::EhFrame(eh_frame),
            (None, _) => ModuleUnwindData::None,
        };

        let text_data = if let Some(text_segment) = file
            .segments()
            .find(|segment| segment.name_bytes() == Ok(Some(b"__TEXT")))
        {
            let (start, size) = text_segment.file_range();
            let address_range = base_avma + start..base_avma + start + size;
            text_segment
                .data()
                .ok()
                .map(|data| TextByteData::new(data.to_owned(), address_range))
        } else if let Some(text_section) = &text {
            if let Some((start, size)) = text_section.file_range() {
                let address_range = base_avma + start..base_avma + start + size;
                text_section
                    .data()
                    .ok()
                    .map(|data| TextByteData::new(data.to_owned(), address_range))
            } else {
                None
            }
        } else {
            None
        };

        fn svma_range<'a>(section: &impl ObjectSection<'a>) -> Range<u64> {
            section.address()..section.address() + section.size()
        }

        let module = Module::new(
            path.to_string(),
            avma_range.clone(),
            base_avma,
            ModuleSvmaInfo {
                base_svma,
                text: text.as_ref().map(svma_range),
                text_env: text_env.as_ref().map(svma_range),
                stubs: None,
                stub_helper: None,
                eh_frame: eh_frame.as_ref().map(svma_range),
                eh_frame_hdr: eh_frame_hdr.as_ref().map(svma_range),
                got: got.as_ref().map(svma_range),
            },
            unwind_data,
            text_data,
        );
        unwinder.add_module(module);

        debug_id = debug_id_for_object(&file)?;
        code_id = file.build_id().ok().flatten().map(CodeId::from_binary);
    } else {
        // Without access to the binary file, make some guesses. We can't really
        // know what the right base address is because we don't have the section
        // information which lets us map between addresses and file offsets, but
        // often svmas and file offsets are the same, so this is a reasonable guess.
        base_avma = mapping_start_avma - mapping_start_file_offset;

        // If we have a build ID, convert it to a debug_id and a code_id.
        debug_id = build_id
            .map(|id| DebugId::from_identifier(id, true)) // TODO: endian
            .unwrap_or_default();
        code_id = build_id.map(CodeId::from_binary);
    }

    let name = objpath
        .file_name()
        .map_or("<unknown>".into(), |f| f.to_string_lossy().to_string());
    // Some(LibraryInfo {
    //     base_avma,
    //     avma_range,
    //     debug_id,
    //     code_id,
    //     path: path.to_string(),
    //     debug_path: path.to_string(),
    //     debug_name: name.clone(),
    //     name,
    //     arch: None,
    // })
    Some(())
}

#[derive(Default)]
pub struct MyUnwinderAarch64 {
    pub unw: UnwinderAarch64<Vec<u8>>,
    pub unw_cache: CacheAarch64<Vec<u8>>,
    pub addr_cache: FxHashSet<u64>,
}

impl MyUnwinderAarch64 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn unwind(&mut self, st: Stack, proc_map: &[MemoryMap]) -> Vec<u64> {
        for entry in proc_map.iter() {
            if !entry.perms.contains('x') {
                continue;
            }
            if !self.addr_cache.contains(&entry.address.0) {
                if let MMapPath::Path(path) = &entry.pathname {
                    add_module_to_unwinder(
                        &mut self.unw,
                        path.as_os_str().as_bytes(),
                        entry.offset,
                        entry.address.0,
                        entry.address.1 - entry.address.0,
                        None,
                        None,
                    );
                    self.addr_cache.insert(entry.address.0);
                }
            }
        }

        fn to_u64_arr(s8: &[u8]) -> &[u64] {
            use std::slice;
            unsafe { slice::from_raw_parts(s8.as_ptr() as *const u64, s8.len() / 8) }
        }

        let mut read_stack = |addr: u64| {
            let offset = addr.checked_sub(st.sp).ok_or(())?;
            let index = usize::try_from(offset / 8).map_err(|_| ())?;
            to_u64_arr(&st.raw_user_stack[..st.user_stack_len]).get(index).copied().ok_or(())
        };

        let mut iter = self.unw.iter_frames(
            st.pc,
            UnwindRegsAarch64::new(st.lr, st.sp, st.fp),
            &mut self.unw_cache,
            &mut read_stack,
        );

        let mut frames = vec![];
        loop {
            match iter.next() {
                // found a frame
                Ok(Some(f)) => frames.push(f.address()),
                // unwinded to root
                Ok(None) => break,
                Err(e) => {
                    error!("Unwinding error: {}", e);
                    break;
                }
            }
        } 

        frames
    }
}

#[cfg(test)]
mod tests {
    use object::File;

    use super::*;

    #[test]
    fn test_compute_img_bias() {
        let path = "/home/g/tail2/testapp/malloc/a.out";
        let objpath = Path::new(path);
        let file = open_file_with_fallback(&objpath, None).unwrap();
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file).unwrap() };
        let file = object::File::parse(&mmap[..]).unwrap();
        println!(
            "{}",
            compute_image_bias(&file, 0, 0xaaaac6cd0000, 0x1000).unwrap()
        );

        let path = "/usr/lib/aarch64-linux-gnu/libc.so.6";
        let objpath = Path::new(path);
        let file = open_file_with_fallback(&objpath, None).unwrap();
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file).unwrap() };
        let file = object::File::parse(&mmap[..]).unwrap();
        println!(
            "{}",
            compute_image_bias(&file, 0, 0xffff87770000, 0xffff878f9000 - 0xffff87770000).unwrap()
        );
    }
}