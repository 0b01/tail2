use crate::runtime_type::RuntimeType;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcMod {
    pub id: u32,
    pub avma: (u64, u64),
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcMod {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcInfo {
    pub mods: [ProcMod; 128],
    pub len: usize,
    pub runtime_type: RuntimeType,
}

impl ProcInfo {
    /// find mod id where ip is in range
    pub fn find_mod_with_ip(&self, ip: u64) -> Option<u32> {
        self.mods
            .iter()
            .filter(|m|m.avma.0 <= ip && ip < m.avma.1)
            .map(|m| m.id)
            .next()
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcInfo {}