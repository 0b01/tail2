use std::{fs, env::args};
use ehframe;
use object::File;

fn main() {
    let path = args().skip(1).next().unwrap();
    let data = fs::read(path).unwrap();
    let obj_file = File::parse(data.as_slice()).unwrap();
    let unwindtable = ehframe::UnwindTable::parse(&obj_file).unwrap();
    dbg!(unwindtable);
}
