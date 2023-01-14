use crate::native::unwinding::error::Error;

macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + count!($($xs)*));
}

/// https://stackoverflow.com/a/64678145/10854888
macro_rules! iterable_enum {
    ($(#[$derives:meta])* $(vis $visibility:vis)? enum $name:ident { $($(#[$nested_meta:meta])* $member:ident),* }) => {
        const COUNT_MEMBERS: usize = count!($($member)*);
        $(#[$derives])*
        $($visibility)? enum $name {
            $($(#[$nested_meta])* $member),*
        }
        impl $name {
            pub const fn iter() -> [$name; COUNT_MEMBERS] {
                [$($name::$member,)*]
            }
        }
    };
}


iterable_enum! {
    #[derive(Copy, Clone, Debug)]
    #[repr(u32)]
    vis pub enum Metrics {
        SentStackCount,
        ErrUnw_InvalidRule,
        ErrUnw_CouldNotReadStack,
        ErrUnw_FramepointerUnwindingMovedBackwards,
        ErrUnw_DidNotAdvance,
        ErrUnw_IntegerOverflow,
        ErrUnw_ReturnAddressIsNull,
        Max
    }
}

impl From<Error> for Metrics {
    fn from(value: Error) -> Self {
        match value {
            Error::InvalidRule => Self::ErrUnw_InvalidRule,
            Error::CouldNotReadStack(_) => Self::ErrUnw_CouldNotReadStack,
            Error::FramepointerUnwindingMovedBackwards => Self::ErrUnw_FramepointerUnwindingMovedBackwards,
            Error::DidNotAdvance => Self::ErrUnw_DidNotAdvance,
            Error::IntegerOverflow => Self::ErrUnw_IntegerOverflow,
            Error::ReturnAddressIsNull => Self::ErrUnw_ReturnAddressIsNull,
        }
    }
}