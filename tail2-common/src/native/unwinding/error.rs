#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidRule,
    CouldNotReadStack(u64),
    FramepointerUnwindingMovedBackwards,
    DidNotAdvance,
    IntegerOverflow,
    ReturnAddressIsNull,
}

#[cfg(feature="user")]
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwinderError {
    #[error("DWARF unwinding failed: {0}")]
    Dwarf(#[from] DwarfUnwinderError),

    #[error("__unwind_info referred to DWARF FDE but we do not have __eh_frame data")]
    NoDwarfData,

    #[error("No unwind data for the module containing the address")]
    NoModuleUnwindData,

    #[error(".eh_frame_hdr was not successful in looking up the address in the table")]
    EhFrameHdrCouldNotFindAddress,

    #[error("Failed to look up the address in the DwarfCfiIndex search table")]
    DwarfCfiIndexCouldNotFindAddress,
}

#[cfg(feature="user")]
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfUnwinderError {
    #[error("Could not get the FDE for the supplied offset: ")]
    FdeFromOffsetFailed,

    #[error("Could not find DWARF unwind info for the requested address: ")]
    UnwindInfoForAddressFailed,

    #[error("Stack pointer moved backwards")]
    StackPointerMovedBackwards,

    #[error("Did not advance")]
    DidNotAdvance,

    #[error("Could not recover the CFA")]
    CouldNotRecoverCfa,

    #[error("Could not recover the return address")]
    CouldNotRecoverReturnAddress,

    #[error("Could not recover the frame pointer")]
    CouldNotRecoverFramePointer,
}

#[cfg(feature="user")]
#[derive(Clone, Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("CfaIsExpression")]
    CfaIsExpression,
    #[error("CfaIsOffsetFromUnknownRegister")]
    CfaIsOffsetFromUnknownRegister,
    #[error("ReturnAddressRuleWithUnexpectedOffset")]
    ReturnAddressRuleWithUnexpectedOffset,
    #[error("ReturnAddressRuleWasWeird")]
    ReturnAddressRuleWasWeird,
    #[error("SpOffsetDoesNotFit")]
    SpOffsetDoesNotFit,
    #[error("RegisterNotStoredRelativeToCfa")]
    RegisterNotStoredRelativeToCfa,
    #[error("RestoringFpButNotLr")]
    RestoringFpButNotLr,
    #[error("LrStorageOffsetDoesNotFit")]
    LrStorageOffsetDoesNotFit,
    #[error("FpStorageOffsetDoesNotFit")]
    FpStorageOffsetDoesNotFit,
    #[error("SpOffsetFromFpDoesNotFit")]
    SpOffsetFromFpDoesNotFit,
    #[error("FramePointerRuleDoesNotRestoreLr")]
    FramePointerRuleDoesNotRestoreLr,
    #[error("FramePointerRuleDoesNotRestoreFp")]
    FramePointerRuleDoesNotRestoreFp,
    #[error("FramePointerRuleDoesNotRestoreBp")]
    FramePointerRuleDoesNotRestoreBp,
    #[error("FramePointerRuleHasStrangeBpOffset")]
    FramePointerRuleHasStrangeBpOffset,
}
