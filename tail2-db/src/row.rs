use tail2::calltree::CallTree;

pub struct DbRow {
    pub ts: i64,
    pub ct: CallTree,
    pub n: i32,
}
