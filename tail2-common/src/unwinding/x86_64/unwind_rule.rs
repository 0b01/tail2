use gimli::{CfaRule, RegisterRule, X86_64};

#[cfg(feature="user")]
use crate::unwinding::error::ConversionError;
use super::unwindregs::UnwindRegsX86_64;

/// For all of these: return address is *(new_sp - 8)
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnwindRuleX86_64 {
    /// (sp, bp) = (sp + 8, bp)
    JustReturn,
    /// (sp, bp) = if is_first_frame (sp + 8, bp) else (bp + 16, *bp)
    JustReturnIfFirstFrameOtherwiseFp,
    /// (sp, bp) = (sp + 8x, bp)
    OffsetSp { sp_offset_by_8: u16 },
    /// (sp, bp) = (sp + 8x, *(sp + 8y))
    OffsetSpAndRestoreBp {
        sp_offset_by_8: u16,
        bp_storage_offset_from_sp_by_8: i16,
    },
    /// (sp, bp) = (bp + 16, *bp)
    UseFramePointer,
}

impl Default for UnwindRuleX86_64 {
    fn default() -> Self {
        Self::JustReturn
    }
}

impl UnwindRuleX86_64 {
    fn rule_for_stub_functions() -> Self {
        UnwindRuleX86_64::JustReturn
    }
    fn rule_for_function_start() -> Self {
        UnwindRuleX86_64::JustReturn
    }
    fn fallback_rule() -> Self {
        UnwindRuleX86_64::UseFramePointer
    }

    pub fn exec<F>(
        self,
        is_first_frame: bool,
        regs: &mut UnwindRegsX86_64,
        read_stack: &mut F,
    ) -> Option<Option<u64>>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let sp = regs.sp();
        let (new_sp, new_bp) = match self {
            UnwindRuleX86_64::JustReturn => {
                let new_sp = sp.checked_add(8)?;
                (new_sp, regs.bp())
            }
            UnwindRuleX86_64::JustReturnIfFirstFrameOtherwiseFp => {
                if is_first_frame {
                    let new_sp = sp.checked_add(8)?;
                    (new_sp, regs.bp())
                } else {
                    let sp = regs.sp();
                    let bp = regs.bp();
                    let new_sp = bp.checked_add(16)?;
                    if new_sp <= sp {
                        return None;
                    }
                    let new_bp = read_stack(bp).ok()?;
                    (new_sp, new_bp)
                }
            }
            UnwindRuleX86_64::OffsetSp { sp_offset_by_8 } => {
                let sp_offset = u64::from(sp_offset_by_8) * 8;
                let new_sp = sp.checked_add(sp_offset)?;
                (new_sp, regs.bp())
            }
            UnwindRuleX86_64::OffsetSpAndRestoreBp {
                sp_offset_by_8,
                bp_storage_offset_from_sp_by_8,
            } => {
                let sp_offset = u64::from(sp_offset_by_8) * 8;
                let new_sp = sp.checked_add(sp_offset)?;
                let bp_storage_offset_from_sp = i64::from(bp_storage_offset_from_sp_by_8) * 8;
                let bp_location = sp.checked_add_signed(bp_storage_offset_from_sp)
                    ?;
                let new_bp = match read_stack(bp_location) {
                    Ok(new_bp) => new_bp,
                    Err(()) if is_first_frame && bp_location < sp => {
                        // Ignore errors when reading beyond the stack pointer in the first frame.
                        // These negative offsets are sometimes seen in x86_64 epilogues, where
                        // a bunch of registers are popped one after the other, and the compiler
                        // doesn't always set the already-popped register to "unchanged" (because
                        // doing so would take up extra space in the dwarf information).
                        // read_stack may legitimately refuse to read beyond the stack pointer,
                        // for example when the stack bytes are coming from a linux perf event
                        // sample record, where the ustack bytes are copied starting from sp.
                        regs.bp()
                    }
                    Err(()) => return None,
                };
                (new_sp, new_bp)
            }
            UnwindRuleX86_64::UseFramePointer => {
                // Do a frame pointer stack walk. Code that is compiled with frame pointers
                // has the following function prologues and epilogues:
                //
                // Function prologue:
                // pushq  %rbp
                // movq   %rsp, %rbp
                //
                // Function epilogue:
                // popq   %rbp
                // ret
                //
                // Functions are called with callq; callq pushes the return address onto the stack.
                // When a function reaches its end, ret pops the return address from the stack and jumps to it.
                // So when a function is called, we have the following stack layout:
                //
                //                                                                     [... rest of the stack]
                //                                                                     ^ rsp           ^ rbp
                //     callq some_function
                //                                                   [return address]  [... rest of the stack]
                //                                                   ^ rsp                             ^ rbp
                //     pushq %rbp
                //                         [caller's frame pointer]  [return address]  [... rest of the stack]
                //                         ^ rsp                                                       ^ rbp
                //     movq %rsp, %rbp
                //                         [caller's frame pointer]  [return address]  [... rest of the stack]
                //                         ^ rsp, rbp
                //     <other instructions>
                //       [... more stack]  [caller's frame pointer]  [return address]  [... rest of the stack]
                //       ^ rsp             ^ rbp
                //
                // So: *rbp is the caller's frame pointer, and *(rbp + 8) is the return address.
                //
                // Or, in other words, the following linked list is built up on the stack:
                // #[repr(C)]
                // struct CallFrameInfo {
                //     previous: *const CallFrameInfo,
                //     return_address: *const c_void,
                // }
                // and rbp is a *const CallFrameInfo.
                let sp = regs.sp();
                let bp = regs.bp();
                if bp == 0 {
                    return Some(None);
                }
                let new_sp = bp.checked_add(16)?;
                if new_sp <= sp {
                    return None;
                }
                let new_bp = read_stack(bp).ok()?;
                // new_bp is the caller's bp. If the caller uses frame pointers, then bp should be
                // a valid frame pointer and we could do a coherency check on new_bp to make sure
                // it's moving in the right direction. But if the caller is using bp as a general
                // purpose register, then any value (including zero) would be a valid value.
                // At this point we don't know how the caller uses bp, so we leave new_bp unchecked.

                (new_sp, new_bp)
            }
        };
        let return_address =
            read_stack(new_sp - 8).ok()?;
        if return_address == 0 {
            return Some(None);
        }
        if new_sp == sp && return_address == regs.ip() {
            return None;
        }
        regs.set_ip(return_address);
        regs.set_sp(new_sp);
        regs.set_bp(new_bp);
        Some(Some(return_address))
    }

    pub fn to_num(&self) -> i32 {
        match self {
            Self::JustReturn => 0,
            Self::JustReturnIfFirstFrameOtherwiseFp => 1,
            Self::OffsetSp { .. } => 2,
            Self::OffsetSpAndRestoreBp { .. } => 3,
            Self::UseFramePointer => 4,
        }
    }
}


#[cfg(feature = "user")]
pub(crate) fn translate_into_unwind_rule<R: gimli::Reader>(
    cfa_rule: &CfaRule<R>,
    bp_rule: &RegisterRule<R>,
    ra_rule: &RegisterRule<R>,
) -> Result<UnwindRuleX86_64, ConversionError> {
    match ra_rule {
        RegisterRule::Undefined => {
            // This is normal. Return address is [CFA-8].
        }
        RegisterRule::Offset(offset) => {
            if *offset == -8 {
                // Weirdly explicit, but also ok.
            } else {
                // Not ok.
                return Err(ConversionError::ReturnAddressRuleWithUnexpectedOffset);
            }
        }
        _ => {
            // Somebody's being extra. Go down the slow path.
            return Err(ConversionError::ReturnAddressRuleWasWeird);
        }
    }

    match cfa_rule {
        CfaRule::RegisterAndOffset { register, offset } => match *register {
            X86_64::RSP => {
                let sp_offset_by_8 =
                    u16::try_from(offset / 8).map_err(|_| ConversionError::SpOffsetDoesNotFit)?;
                let fp_cfa_offset = register_rule_to_cfa_offset(bp_rule)?;
                match fp_cfa_offset {
                    None => Ok(UnwindRuleX86_64::OffsetSp { sp_offset_by_8 }),
                    Some(bp_cfa_offset) => {
                        let bp_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + bp_cfa_offset) / 8)
                                .map_err(|_| ConversionError::FpStorageOffsetDoesNotFit)?;
                        Ok(UnwindRuleX86_64::OffsetSpAndRestoreBp {
                            sp_offset_by_8,
                            bp_storage_offset_from_sp_by_8,
                        })
                    }
                }
            }
            X86_64::RBP => {
                let bp_cfa_offset = register_rule_to_cfa_offset(bp_rule)?
                    .ok_or(ConversionError::FramePointerRuleDoesNotRestoreBp)?;
                if *offset == 16 && bp_cfa_offset == -16 {
                    Ok(UnwindRuleX86_64::UseFramePointer)
                } else {
                    // TODO: Maybe handle this case. This case has been observed in _ffi_call_unix64,
                    // which has the following unwind table:
                    //
                    // 00000060 00000024 0000001c FDE cie=00000048 pc=000de548...000de6a6
                    //   0xde548: CFA=reg7+8: reg16=[CFA-8]
                    //   0xde562: CFA=reg6+32: reg6=[CFA-16], reg16=[CFA-8]
                    //   0xde5ad: CFA=reg7+8: reg16=[CFA-8]
                    //   0xde668: CFA=reg7+8: reg6=[CFA-16], reg16=[CFA-8]
                    Err(ConversionError::FramePointerRuleHasStrangeBpOffset)
                }
            }
            _ => Err(ConversionError::CfaIsOffsetFromUnknownRegister),
        },
        CfaRule::Expression(_) => Err(ConversionError::CfaIsExpression),
    }
}

#[cfg(feature = "user")]
pub(crate) fn register_rule_to_cfa_offset<R: gimli::Reader>(
    rule: &RegisterRule<R>,
) -> Result<Option<i64>, ConversionError> {
    match *rule {
        RegisterRule::Undefined | RegisterRule::SameValue => Ok(None),
        RegisterRule::Offset(offset) => Ok(Some(offset)),
        _ => Err(ConversionError::RegisterNotStoredRelativeToCfa),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic() {
        let stack = [
            1, 2, 0x100300, 4, 0x40, 0x100200, 5, 6, 0x70, 0x100100, 7, 8, 9, 10, 0x0, 0x0,
        ];
        let mut read_stack = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsX86_64::new(0x100400, 0x10, 0x20);
        let res =
            UnwindRuleX86_64::OffsetSp { sp_offset_by_8: 1 }.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Some(Some(0x100300)));
        assert_eq!(regs.ip(), 0x100300);
        assert_eq!(regs.sp(), 0x18);
        assert_eq!(regs.bp(), 0x20);
        let res = UnwindRuleX86_64::UseFramePointer.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Some(Some(0x100200)));
        assert_eq!(regs.ip(), 0x100200);
        assert_eq!(regs.sp(), 0x30);
        assert_eq!(regs.bp(), 0x40);
        let res = UnwindRuleX86_64::UseFramePointer.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Some(Some(0x100100)));
        assert_eq!(regs.ip(), 0x100100);
        assert_eq!(regs.sp(), 0x50);
        assert_eq!(regs.bp(), 0x70);
        let res = UnwindRuleX86_64::UseFramePointer.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Some(None));
    }

    #[test]
    fn test_overflow() {
        // This test makes sure that debug builds don't panic when trying to use frame pointer
        // unwinding on code that was using the bp register as a general-purpose register and
        // storing -1 in it. -1 is u64::MAX, so an unchecked add panics in debug builds.
        let stack = [
            1, 2, 0x100300, 4, 0x40, 0x100200, 5, 6, 0x70, 0x100100, 7, 8, 9, 10, 0x0, 0x0,
        ];
        let mut read_stack = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsX86_64::new(0x100400, u64::MAX / 8 * 8, u64::MAX);
        let res = UnwindRuleX86_64::JustReturn.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, None);
        let res =
            UnwindRuleX86_64::OffsetSp { sp_offset_by_8: 1 }.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, None);
        let res = UnwindRuleX86_64::OffsetSpAndRestoreBp {
            sp_offset_by_8: 1,
            bp_storage_offset_from_sp_by_8: 2,
        }
        .exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, None);
        let res = UnwindRuleX86_64::UseFramePointer.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, None);
    }
}