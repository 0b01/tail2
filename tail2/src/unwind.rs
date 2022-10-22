use std::{path::{Path, PathBuf}, ops::Range};

use debugid::{CodeId, DebugId};
use framehop::{Unwinder, Module, ModuleUnwindData, TextByteData, ModuleSvmaInfo};
use object::{ObjectSection, Object, ObjectSegment, SectionKind};

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
        // eprintln!("Could not open file {:?}", objpath);
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
                eprintln!("Could not mmap file {}: {:?}", path, err);
                return None;
            }
        };

        fn section_data<'a>(section: &impl ObjectSection<'a>) -> Option<Vec<u8>> {
            section.data().ok().map(|data| data.to_owned())
        }

        let file = match object::File::parse(&mmap[..]) {
            Ok(file) => file,
            Err(_) => {
                eprintln!("File {:?} has unrecognized format", objpath);
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
                        "File {:?} has non-matching build ID {} (expected {})",
                        objpath, file_build_id, expected_build_id
                    );
                    return None;
                }
                None => {
                    eprintln!(
                        "File {:?} does not contain a build ID, but we expected it to have one",
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

use std::convert::TryInto;
use uuid::Uuid;

pub trait DebugIdExt {
    /// Creates a DebugId from some identifier. The identifier could be
    /// an ELF build ID, or a hash derived from the text section.
    /// The `little_endian` argument specifies whether the object file
    /// is targeting a little endian architecture.
    fn from_identifier(identifier: &[u8], little_endian: bool) -> Self;

    /// Creates a DebugId from a hash of the first 4096 bytes of the .text section.
    /// The `little_endian` argument specifies whether the object file
    /// is targeting a little endian architecture.
    fn from_text_first_page(text_first_page: &[u8], little_endian: bool) -> Self;
}

impl DebugIdExt for DebugId {
    fn from_identifier(identifier: &[u8], little_endian: bool) -> Self {
        // Make sure that we have exactly 16 bytes available, either truncate or fill
        // the remainder with zeros.
        // ELF build IDs are usually 20 bytes, so if the identifier is an ELF build ID
        // then we're performing a lossy truncation.
        let mut d = [0u8; 16];
        let shared_len = identifier.len().min(d.len());
        d[0..shared_len].copy_from_slice(&identifier[0..shared_len]);

        // Pretend that the build ID was stored as a UUID with u32 u16 u16 fields inside
        // the file. Parse those fields in the endianness of the file. Then use
        // Uuid::from_fields to serialize them as big endian.
        // For ELF build IDs this is a bit silly, because ELF build IDs aren't actually
        // field-based UUIDs, but this is what the tools in the breakpad and
        // sentry/symbolic universe do, so we do the same for compatibility with those
        // tools.
        let (d1, d2, d3) = if little_endian {
            (
                u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
                u16::from_le_bytes([d[4], d[5]]),
                u16::from_le_bytes([d[6], d[7]]),
            )
        } else {
            (
                u32::from_be_bytes([d[0], d[1], d[2], d[3]]),
                u16::from_be_bytes([d[4], d[5]]),
                u16::from_be_bytes([d[6], d[7]]),
            )
        };
        let uuid = Uuid::from_fields(d1, d2, d3, d[8..16].try_into().unwrap());
        DebugId::from_uuid(uuid)
    }

    // This algorithm XORs 16-byte chunks directly into a 16-byte buffer.
    fn from_text_first_page(text_first_page: &[u8], little_endian: bool) -> Self {
        const UUID_SIZE: usize = 16;
        const PAGE_SIZE: usize = 4096;
        let mut hash = [0; UUID_SIZE];
        for (i, byte) in text_first_page.iter().cloned().take(PAGE_SIZE).enumerate() {
            hash[i % UUID_SIZE] ^= byte;
        }
        DebugId::from_identifier(&hash, little_endian)
    }
}

/// Tries to obtain a DebugId for an object. This uses the build ID, if available,
/// and falls back to hashing the first page of the text section otherwise.
/// Returns None on failure.
pub fn debug_id_for_object<'data: 'file, 'file>(
    obj: &'file impl Object<'data, 'file>,
) -> Option<DebugId> {
    // Windows
    if let Ok(Some(pdb_info)) = obj.pdb_info() {
        return Some(DebugId::from_guid_age(&pdb_info.guid(), pdb_info.age()).unwrap());
    }

    // ELF
    if let Ok(Some(build_id)) = obj.build_id() {
        return Some(DebugId::from_identifier(build_id, obj.is_little_endian()));
    }

    // mach-O
    if let Ok(Some(uuid)) = obj.mach_uuid() {
        return Some(DebugId::from_uuid(Uuid::from_bytes(uuid)));
    }

    // We were not able to locate a build ID, so fall back to creating a synthetic
    // identifier from a hash of the first page of the "text" (program code) section.
    if let Some(section) = obj
        .sections()
        .find(|section| section.kind() == SectionKind::Text)
    {
        let data_len = section.size().min(4096);
        if let Ok(Some(first_page_data)) = section.data_range(section.address(), data_len) {
            return Some(DebugId::from_text_first_page(
                first_page_data,
                obj.is_little_endian(),
            ));
        }
    }

    None
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
        println!("{}", compute_image_bias(&file, 0, 0xaaaac6cd0000, 0x1000).unwrap());


        let path = "/usr/lib/aarch64-linux-gnu/libc.so.6";
        let objpath = Path::new(path);
        let file = open_file_with_fallback(&objpath, None).unwrap();
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file).unwrap() };
        let file = object::File::parse(&mmap[..]).unwrap();
        println!("{}", compute_image_bias(&file, 0, 0xffff87770000, 0xffff878f9000 - 0xffff87770000).unwrap());
    }
}