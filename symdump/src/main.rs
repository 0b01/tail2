use std::{path::Path, borrow::Cow};

use anyhow::Result;
use symbolic::{common::ByteView, debuginfo::elf::ElfObject, demangle::demangle};

fn main() -> Result<()> {
    dump_elf(std::env::args().skip(1).next().unwrap())
}

fn dump_elf<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    let buffer = ByteView::open(&path)?;
    let obj = ElfObject::parse(&buffer)?;

    println!("{}", path.display());
    println!("\tarch: {}", obj.arch());
    println!("\tkind: {:?}", obj.kind());
    println!("\tdebug_id: {}", obj.debug_id());
    println!("\thas_syms: {}", obj.has_symbols());
    println!("\tsymbols: ");
    for sym in obj.symbol_map() {
        let name = sym.name().map(demangle).unwrap_or(Cow::default());
        println!("\t\t0x{:x}\t{}", sym.address, name);
    }

    Ok(())
}
