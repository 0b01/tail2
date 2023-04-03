use core::hash::{Hash, Hasher};

#[cfg_attr(feature="user", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Eq)]
pub struct PidTgid(u64);

impl PartialEq for PidTgid {
    fn eq(&self, other: &Self) -> bool {
        self.tgid() == other.tgid()
    }
}

impl Hash for PidTgid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tgid().hash(state);
    }
}

impl Default for PidTgid {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "user")]
impl ToString for PidTgid {
    fn to_string(&self) -> String {
        format!("{}:{}", self.pid(), self.tgid())
    }
}

impl PidTgid {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn current(pid: u32, tgid: u32) -> Self {
        Self((pid as u64) << 32 | tgid as u64)
    }

    #[inline(always)]
    pub fn pid(&self) -> u32 {
        (self.0 >> 32) as _
    }

    #[inline(always)]
    pub fn tgid(&self) -> u32 {
        (self.0 & 0xffffffff) as _
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
