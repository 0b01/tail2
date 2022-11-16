use std::{path::Path};
use anyhow::{Result, Context};
use symbolic::{common::ByteView, debuginfo::elf::ElfObject, demangle::demangle};

pub fn dump_elf<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    let buffer = ByteView::open(path)?;
    let obj = ElfObject::parse(&buffer)?;

    println!("{}", path.display());
    println!("\tarch: {}", obj.arch());
    println!("\tkind: {:?}", obj.kind());
    println!("\tdebug_id: {}", obj.debug_id());
    println!("\thas_syms: {}", obj.has_symbols());
    println!("\tsymbols: ");
    for sym in obj.symbol_map() {
        let name = sym.name().map(demangle).unwrap_or_default();
        println!("\t\t0x{:x}\t{}", sym.address, name);
    }

    Ok(())
}

pub fn lookup<P: AsRef<Path>>(path: P, address: u64) -> Result<String> {
    let path = path.as_ref();
    let buffer = ByteView::open(path)?;
    let obj = ElfObject::parse(&buffer)?;
    obj.symbol_map()
        .lookup(address)
        .context("not found")
        .map(|s|
            s.name.as_deref()
            .unwrap_or("")
            .to_owned())
        .map(|n|demangle(&n).to_string())
}