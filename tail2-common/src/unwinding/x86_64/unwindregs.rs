#[repr(C)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindRegsX86_64 {
    ip: u64,
    sp: u64,
    bp: u64,
}

impl UnwindRegsX86_64 {
    pub fn new(ip: u64, sp: u64, bp: u64) -> Self {
        Self { ip, sp, bp }
    }

    #[inline(always)]
    pub fn ip(&self) -> u64 {
        self.ip
    }
    #[inline(always)]
    pub fn set_ip(&mut self, ip: u64) {
        self.ip = ip
    }

    #[inline(always)]
    pub fn sp(&self) -> u64 {
        self.sp
    }
    #[inline(always)]
    pub fn set_sp(&mut self, sp: u64) {
        self.sp = sp
    }

    #[inline(always)]
    pub fn bp(&self) -> u64 {
        self.bp
    }
    #[inline(always)]
    pub fn set_bp(&mut self, bp: u64) {
        self.bp = bp
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UnwindRegsX86_64 {}