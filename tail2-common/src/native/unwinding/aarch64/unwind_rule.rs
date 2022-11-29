use gimli::{CfaRule, RegisterRule};

#[cfg(feature="user")]
use crate::native::unwinding::error::ConversionError;

use super::unwindregs::UnwindRegsAarch64;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnwindRuleAarch64 {
    /// (sp, fp, lr) = (sp, fp, lr)
    /// Only possible for the first frame. Subsequent frames must get the
    /// return address from somewhere other than the lr register to avoid
    /// infinite loops.
    NoOp,
    /// (sp, fp, lr) = if is_first_frame (sp, fp, lr) else (fp + 16, *fp, *(fp + 8))
    /// Used as a fallback rule.
    NoOpIfFirstFrameOtherwiseFp,
    /// (sp, fp, lr) = (sp + 16x, fp, lr)
    /// Only possible for the first frame. Subsequent frames must get the
    /// return address from somewhere other than the lr register to avoid
    /// infinite loops.
    OffsetSp { sp_offset_by_16: u16 },
    /// (sp, fp, lr) = (sp + 16x, fp, lr) if is_first_frame
    /// This rule reflects an ambiguity in DWARF CFI information. When the
    /// return address is "undefined" because it was omitted, it could mean
    /// "same value", but this is only allowed for the first frame.
    OffsetSpIfFirstFrameOtherwiseStackEndsHere { sp_offset_by_16: u16 },
    /// (sp, fp, lr) = (sp + 16x, fp, *(sp + 8y))
    OffsetSpAndRestoreLr {
        sp_offset_by_16: u16,
        lr_storage_offset_from_sp_by_8: i16,
    },
    /// (sp, fp, lr) = (sp + 16x, *(sp + 8y), *(sp + 8z))
    OffsetSpAndRestoreFpAndLr {
        sp_offset_by_16: u16,
        fp_storage_offset_from_sp_by_8: i16,
        lr_storage_offset_from_sp_by_8: i16,
    },
    /// (sp, fp, lr) = (fp + 16, *fp, *(fp + 8))
    UseFramePointer,
    /// (sp, fp, lr) = (fp + 8x, *(fp + 8y), *(fp + 8z))
    UseFramepointerWithOffsets {
        sp_offset_from_fp_by_8: u16,
        fp_storage_offset_from_fp_by_8: i16,
        lr_storage_offset_from_fp_by_8: i16,
    },
}

impl Default for UnwindRuleAarch64 {
    fn default() -> Self {
        Self::NoOp
    }
}

impl UnwindRuleAarch64 {
    pub fn exec<F>(
        self,
        is_first_frame: bool,
        regs: &mut UnwindRegsAarch64,
        read_stack: &mut F,
    ) -> Option<Option<u64>>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let lr = regs.lr();
        let sp = regs.sp();
        let fp = regs.fp();

        let (new_lr, new_sp, new_fp) = match self {
            UnwindRuleAarch64::NoOp => {
                if !is_first_frame {
                    return None;
                }
                (lr, sp, fp)
            }
            UnwindRuleAarch64::NoOpIfFirstFrameOtherwiseFp => {
                if is_first_frame {
                    (lr, sp, fp)
                } else {
                    let fp = regs.fp();
                    let new_sp = fp.checked_add(16)?;
                    let new_lr =
                        read_stack(fp + 8).ok()?;
                    let new_fp = read_stack(fp).ok()?;
                    if new_sp <= sp {
                        return None;
                    }
                    (new_lr, new_sp, new_fp)
                }
            }
            UnwindRuleAarch64::OffsetSpIfFirstFrameOtherwiseStackEndsHere { sp_offset_by_16 } => {
                if !is_first_frame {
                    return Some(None);
                }
                let sp_offset = u64::from(sp_offset_by_16) * 16;
                let new_sp = sp.checked_add(sp_offset)?;
                (lr, new_sp, fp)
            }
            UnwindRuleAarch64::OffsetSp { sp_offset_by_16 } => {
                if !is_first_frame {
                    return None;
                }
                let sp_offset = u64::from(sp_offset_by_16) * 16;
                let new_sp = sp.checked_add(sp_offset)?;
                (lr, new_sp, fp)
            }
            UnwindRuleAarch64::OffsetSpAndRestoreLr {
                sp_offset_by_16,
                lr_storage_offset_from_sp_by_8,
            } => {
                let sp_offset = u64::from(sp_offset_by_16) * 16;
                let new_sp = sp.checked_add(sp_offset)?;
                let lr_storage_offset = i64::from(lr_storage_offset_from_sp_by_8) * 8;
                let lr_location =
                    sp.checked_add_signed(lr_storage_offset)?;
                let new_lr =
                    read_stack(lr_location).ok()?;
                (new_lr, new_sp, fp)
            }
            UnwindRuleAarch64::OffsetSpAndRestoreFpAndLr {
                sp_offset_by_16,
                fp_storage_offset_from_sp_by_8,
                lr_storage_offset_from_sp_by_8,
            } => {
                let sp_offset = u64::from(sp_offset_by_16) * 16;
                let new_sp = sp.checked_add(sp_offset)?;
                let lr_storage_offset = i64::from(lr_storage_offset_from_sp_by_8) * 8;
                let lr_location =
                    sp.checked_add_signed(lr_storage_offset)?;
                let new_lr =
                    read_stack(lr_location).ok()?;
                let fp_storage_offset = i64::from(fp_storage_offset_from_sp_by_8) * 8;
                let fp_location =
                    sp.checked_add_signed(fp_storage_offset)?;
                let new_fp =
                    read_stack(fp_location).ok()?;
                (new_lr, new_sp, new_fp)
            }
            UnwindRuleAarch64::UseFramePointer => {
                // Do a frame pointer stack walk. Frame-based aarch64 functions store the caller's fp and lr
                // on the stack and then set fp to the address where the caller's fp is stored.
                //
                // Function prologue example (this one also stores x19, x20, x21 and x22):
                // stp  x22, x21, [sp, #-0x30]! ; subtracts 0x30 from sp, and then stores (x22, x21) at sp
                // stp  x20, x19, [sp, #0x10]   ; stores (x20, x19) at sp + 0x10 (== original sp - 0x20)
                // stp  fp, lr, [sp, #0x20]     ; stores (fp, lr) at sp + 0x20 (== original sp - 0x10)
                // add  fp, sp, #0x20           ; sets fp to the address where the old fp is stored on the stack
                //
                // Function epilogue:
                // ldp  fp, lr, [sp, #0x20]     ; restores fp and lr from the stack
                // ldp  x20, x19, [sp, #0x10]   ; restores x20 and x19
                // ldp  x22, x21, [sp], #0x30   ; restores x22 and x21, and then adds 0x30 to sp
                // ret                          ; follows lr to jump back to the caller
                //
                // Functions are called with bl ("branch with link"); bl puts the return address into the lr register.
                // When a function reaches its end, ret reads the return address from lr and jumps to it.
                // On aarch64, the stack pointer is always aligned to 16 bytes, and registers are usually written
                // to and read from the stack in pairs.
                // In frame-based functions, fp and lr are placed next to each other on the stack.
                // So when a function is called, we have the following stack layout:
                //
                //                                                                      [... rest of the stack]
                //                                                                      ^ sp           ^ fp
                //     bl some_function          ; jumps to the function and sets lr = return address
                //                                                                      [... rest of the stack]
                //                                                                      ^ sp           ^ fp
                //     adjust stack ptr, write some registers, and write fp and lr
                //       [more saved regs]  [caller's frame pointer]  [return address]  [... rest of the stack]
                //       ^ sp                                                                          ^ fp
                //     add    fp, sp, #0x20      ; sets fp to where the caller's fp is now stored
                //       [more saved regs]  [caller's frame pointer]  [return address]  [... rest of the stack]
                //       ^ sp               ^ fp
                //     <function contents>       ; can execute bl and overwrite lr with a new value
                //  ...  [more saved regs]  [caller's frame pointer]  [return address]  [... rest of the stack]
                //  ^ sp                    ^ fp
                //
                // So: *fp is the caller's frame pointer, and *(fp + 8) is the return address.
                let fp = regs.fp();
                let new_sp = fp.checked_add(16)?;
                let new_lr = read_stack(fp + 8).ok()?;
                let new_fp = read_stack(fp).ok()?;
                if new_fp == 0 {
                    return Some(None);
                }
                if new_fp <= fp || new_sp <= sp {
                    return None;
                }
                (new_lr, new_sp, new_fp)
            }
            UnwindRuleAarch64::UseFramepointerWithOffsets {
                sp_offset_from_fp_by_8,
                fp_storage_offset_from_fp_by_8,
                lr_storage_offset_from_fp_by_8,
            } => {
                let sp_offset_from_fp = u64::from(sp_offset_from_fp_by_8) * 8;
                let new_sp = fp
                    .checked_add(sp_offset_from_fp)
                    ?;
                let lr_storage_offset = i64::from(lr_storage_offset_from_fp_by_8) * 8;
                let lr_location =
                    fp.checked_add_signed(lr_storage_offset)?;
                let new_lr =
                    read_stack(lr_location).ok()?;
                let fp_storage_offset = i64::from(fp_storage_offset_from_fp_by_8) * 8;
                let fp_location =
                    fp.checked_add_signed(fp_storage_offset)?;
                let new_fp =
                    read_stack(fp_location).ok()?;

                if new_fp == 0 {
                    return Some(None);
                }
                if new_fp <= fp || new_sp <= sp {
                    return None;
                }
                (new_lr, new_sp, new_fp)
            }
        };
        let return_address = regs.lr_mask().strip_ptr_auth(new_lr);
        if return_address == 0 {
            return Some(None);
        }
        if !is_first_frame && new_sp == sp {
            return None;
        }
        regs.set_lr(new_lr);
        regs.set_sp(new_sp);
        regs.set_fp(new_fp);

        Some(Some(return_address))
    }

    pub fn as_num(&self) -> u32 {
        match &self {
            UnwindRuleAarch64::NoOp => 0,
            UnwindRuleAarch64::NoOpIfFirstFrameOtherwiseFp => 1,
            UnwindRuleAarch64::OffsetSp { sp_offset_by_16 } => 2,
            UnwindRuleAarch64::OffsetSpIfFirstFrameOtherwiseStackEndsHere { sp_offset_by_16 } => 3,
            UnwindRuleAarch64::OffsetSpAndRestoreLr { sp_offset_by_16, lr_storage_offset_from_sp_by_8 } => 4,
            UnwindRuleAarch64::OffsetSpAndRestoreFpAndLr { sp_offset_by_16, fp_storage_offset_from_sp_by_8, lr_storage_offset_from_sp_by_8 } => 5,
            UnwindRuleAarch64::UseFramePointer => 6,
            UnwindRuleAarch64::UseFramepointerWithOffsets { sp_offset_from_fp_by_8, fp_storage_offset_from_fp_by_8, lr_storage_offset_from_fp_by_8 } => 7,
        }
    }
}

#[cfg(feature="user")]
pub(crate) fn translate_into_unwind_rule<R: gimli::Reader>(
    cfa_rule: &CfaRule<R>,
    fp_rule: &RegisterRule<R>,
    lr_rule: &RegisterRule<R>,
) -> Result<UnwindRuleAarch64, ConversionError> {
    match cfa_rule {
        CfaRule::RegisterAndOffset { register, offset } => match *register {
            gimli::AArch64::SP => {
                let sp_offset_by_16 =
                    u16::try_from(offset / 16).map_err(|_| ConversionError::SpOffsetDoesNotFit)?;
                let lr_cfa_offset = register_rule_to_cfa_offset(lr_rule)?;
                let fp_cfa_offset = register_rule_to_cfa_offset(fp_rule)?;
                match (lr_cfa_offset, fp_cfa_offset) {
                    (None, Some(_)) => Err(ConversionError::RestoringFpButNotLr),
                    (None, None) => {
                        if let RegisterRule::Undefined = lr_rule {
                            // If the return address is undefined, this could have two reasons:
                            //  - The column for the return address may have been manually set to "undefined"
                            //    using DW_CFA_undefined. This usually means that the function never returns
                            //    and can be treated as the root of the stack.
                            //  - The column for the return may have been omitted from the DWARF CFI table.
                            //    Per spec (at least as of DWARF >= 3), this means that it should be treated
                            //    as undefined. But it seems that compilers often do this when they really mean
                            //    "same value".
                            // Gimli follows DWARF 3 and does not differentiate between "omitted" and "undefined".
                            Ok(
                                UnwindRuleAarch64::OffsetSpIfFirstFrameOtherwiseStackEndsHere {
                                    sp_offset_by_16,
                                },
                            )
                        } else {
                            Ok(UnwindRuleAarch64::OffsetSp { sp_offset_by_16 })
                        }
                    }
                    (Some(lr_cfa_offset), None) => {
                        let lr_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + lr_cfa_offset) / 8)
                                .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                        Ok(UnwindRuleAarch64::OffsetSpAndRestoreLr {
                            sp_offset_by_16,
                            lr_storage_offset_from_sp_by_8,
                        })
                    }
                    (Some(lr_cfa_offset), Some(fp_cfa_offset)) => {
                        let lr_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + lr_cfa_offset) / 8)
                                .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                        let fp_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + fp_cfa_offset) / 8)
                                .map_err(|_| ConversionError::FpStorageOffsetDoesNotFit)?;
                        Ok(UnwindRuleAarch64::OffsetSpAndRestoreFpAndLr {
                            sp_offset_by_16,
                            fp_storage_offset_from_sp_by_8,
                            lr_storage_offset_from_sp_by_8,
                        })
                    }
                }
            }
            gimli::AArch64::X29 => {
                let lr_cfa_offset = register_rule_to_cfa_offset(lr_rule)?
                    .ok_or(ConversionError::FramePointerRuleDoesNotRestoreLr)?;
                let fp_cfa_offset = register_rule_to_cfa_offset(fp_rule)?
                    .ok_or(ConversionError::FramePointerRuleDoesNotRestoreFp)?;
                if *offset == 16 && fp_cfa_offset == -16 && lr_cfa_offset == -8 {
                    Ok(UnwindRuleAarch64::UseFramePointer)
                } else {
                    let sp_offset_from_fp_by_8 = u16::try_from(offset / 8)
                        .map_err(|_| ConversionError::SpOffsetFromFpDoesNotFit)?;
                    let lr_storage_offset_from_fp_by_8 =
                        i16::try_from((offset + lr_cfa_offset) / 8)
                            .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                    let fp_storage_offset_from_fp_by_8 =
                        i16::try_from((offset + fp_cfa_offset) / 8)
                            .map_err(|_| ConversionError::FpStorageOffsetDoesNotFit)?;
                    Ok(UnwindRuleAarch64::UseFramepointerWithOffsets {
                        sp_offset_from_fp_by_8,
                        fp_storage_offset_from_fp_by_8,
                        lr_storage_offset_from_fp_by_8,
                    })
                }
            }
            _ => Err(ConversionError::CfaIsOffsetFromUnknownRegister),
        },
        CfaRule::Expression(_) => Err(ConversionError::CfaIsExpression),
    }
}

#[cfg(feature="user")]
pub(crate) fn register_rule_to_cfa_offset<R: gimli::Reader>(
    rule: &RegisterRule<R>,
) -> Result<Option<i64>, ConversionError> {
    match *rule {
        RegisterRule::Undefined | RegisterRule::SameValue => Ok(None),
        RegisterRule::Offset(offset) => Ok(Some(offset)),
        _ => Err(ConversionError::RegisterNotStoredRelativeToCfa),
    }
}
