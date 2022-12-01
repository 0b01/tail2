use anyhow::Result;
use gimli::{NativeEndian, Reader, UnwindContext, UnwindSection, X86_64};
use object::{Object, ObjectSection};
use super::unwind_rule::{UnwindRuleX86_64, translate_into_unwind_rule};

/// Row of a FDE.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct UnwindTableRow {
    /// Instruction pointer start range (inclusive).
    pub start_address: usize,
    // /// Instruction pointer end range (exclusive).
    // pub end_address: u64,
    /// unwind rule
    pub rule: UnwindRuleX86_64,
}

impl UnwindTableRow {
    pub fn parse<R: Eq + Reader>(
        row: &gimli::UnwindTableRow<R>,
        _encoding: gimli::Encoding,
    ) -> Result<Self> {
        let cfa_rule = row.cfa();
        let bp_rule = row.register(X86_64::RBP);
        let ra_rule = row.register(X86_64::RA);
        let rule = translate_into_unwind_rule(cfa_rule, &bp_rule, &ra_rule)?;

        Ok(Self {
            start_address: row.start_address() as usize,
            // end_address: row.end_address(),
            rule,
        })
    }

    pub fn invalid(start_address: usize) -> Self {
        Self {
            start_address,
            rule: UnwindRuleX86_64::Invalid,
        }
    }
}

/// Unwind table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnwindTable {
    pub rows: Vec<UnwindTableRow>,
}

impl UnwindTable {
    pub fn from_path(p: &str) -> anyhow::Result<Self> {
        let file = std::fs::File::open(p)?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file).unwrap() };
        let file = object::File::parse(&mmap[..]).unwrap();
        UnwindTable::parse(&file)
    }

    pub fn parse<'a, O: Object<'a, 'a>>(file: &'a O) -> Result<Self> {
        let section = file.section_by_name(".eh_frame").unwrap();
        let data = section.uncompressed_data()?;
        let mut eh_frame = gimli::EhFrame::new(&data, NativeEndian);
        eh_frame.set_address_size(std::mem::size_of::<usize>() as _);

        let mut bases = gimli::BaseAddresses::default();
        if let Some(section) = file.section_by_name(".eh_frame_hdr") {
            bases = bases.set_eh_frame_hdr(section.address());
        }
        if let Some(section) = file.section_by_name(".eh_frame") {
            bases = bases.set_eh_frame(section.address());
        }
        if let Some(section) = file.section_by_name(".text") {
            bases = bases.set_text(section.address());
        }
        if let Some(section) = file.section_by_name(".got") {
            bases = bases.set_got(section.address());
        }

        let mut ctx = UnwindContext::new();
        let mut entries = eh_frame.entries(&bases);
        let mut rows = vec![];
        while let Some(entry) = entries.next()? {
            match entry {
                gimli::CieOrFde::Cie(_) => {}
                gimli::CieOrFde::Fde(partial) => {
                    let fde = partial.parse(|_, bases, o| eh_frame.cie_from_offset(bases, o))?;
                    let encoding = fde.cie().encoding();
                    let mut table = fde.rows(&eh_frame, &bases, &mut ctx)?;
                    while let Some(row) = table.next_row()? {
                        match UnwindTableRow::parse(row, encoding) {
                            Ok(r) => rows.push(r),
                            Err(e) => {
                                eprintln!("err parsing: {}, error: {:?}", row.start_address(), e);
                                rows.push(UnwindTableRow::invalid(row.start_address() as usize));
                            }
                        }
                    }
                }
            }
        }
        rows.sort_unstable_by_key(|row| row.start_address);
        Ok(Self { rows })
    }
}