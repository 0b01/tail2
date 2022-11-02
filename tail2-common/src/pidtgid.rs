
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PidTgid(u64);

impl PidTgid {
    pub fn current(pid: u32, tgid: u32) -> Self {
        Self((pid as u64) << 32 | tgid as u64)
    }

    pub fn pid(&self) -> u32 {
        (self.0 >> 32) as _
    }

    pub fn tgid(&self) -> u32 {
        (self.0 & 0xf) as _
    }
}

impl core::fmt::Debug for PidTgid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PidTgid")
            .field(&self.pid())
            .field(&self.tgid())
            .finish()
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PidTgid {}