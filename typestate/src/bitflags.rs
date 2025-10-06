use core::marker::PhantomData;

pub trait FieldSpec<Reg> {
    const OFF: u32;
    const SZ: u32;
}

pub trait FieldReadable<Reg>: FieldSpec<Reg> {}

pub trait FieldWritable<Reg>: FieldSpec<Reg> {}

pub struct Field<Reg, const OFF: u32, const SZ: u32>(pub PhantomData<Reg>);

impl<Reg, const OFF: u32, const SZ: u32> FieldSpec<Reg> for Field<Reg, OFF, SZ> {
    const OFF: u32 = OFF;
    const SZ: u32 = SZ;
}

impl<Reg, const OFF: u32, const SZ: u32> Field<Reg, OFF, SZ> {
    #[inline]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

/// bitregs macro
///
/// - Integer types: u8 / u16 / u32 / u64 / u128
/// - Bit ranges: `@[MSB:LSB]` (ARM-like) or `(offset, size)`
/// - Union views use absolute bit positions (`@[MSB:LSB]` relative to the register)
/// - Every `union` must be fully covered by its views; offsets written inside each `view`
///   are still absolute and checked against the union span
/// - Reserved: `reserved@[..] [res0|res1|ignore]` / `reserved(off, sz) [..]`
/// - Compile-time checks:
///   * Every item fits into the register width
///   * **Full coverage**: every bit is covered by a field or reserved
///   * **No overlap**: any two regions do not overlap
///   * Enum values fit the declared width
/// - `bits()` **applies res0/res1 policy** (encode integrated)
/// - `new()`/`Default` start with res1 bits set, res0 cleared
///
/// Usage:
/// 'Foo::new().set(Foo::bar1, 0b1).set_enum(Foo::bar2, Bar2::baz1).bits();'
///
/// Example:
/// ```rust
/// use typestate::bitregs;
/// bitregs!{
///     pub struct Foo: u32 {
///         pub bar1@[3:0],
///         reserved@[7:4] [res0],
///         pub bar2@[9:8] as Bar2 {
///             baz1 = 0b01,
///             baz2 = 0b10,
///             baz3 = 0b11,
///         },
///         reserved@[31:10] [ignore],
///     }
/// }
///
/// bitregs!{
///     pub struct WithUnion: u32 {
///         union view0@[15:0] {
///             view Words {
///                 pub low@[7:0],
///                 pub high@[15:8],
///             },
///             view Raw {
///                 pub value@[15:0],
///             },
///         },
///         reserved@[31:16] [ignore],
///     }
/// }
/// ```
#[macro_export]
macro_rules! bitregs {
    // Entry: `struct Name : Ty { ... }`
    ( $(#[$m:meta])* $vis:vis struct $Name:ident : $ty:ty { $($body:tt)* } ) => {
        $(#[$m])*
        #[repr(transparent)]
        #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash /*, ::typestate_macro::RawReg*/)]
        $vis struct $Name($ty);

        const _: () = {
            let cond = (0 as $ty) < (!0 as $ty);
            let _ = [()][(!cond) as usize];
        };

        impl $Name {
            // --- Construction -------------------------------------------------
            /// Construct from raw bits (unchecked).
            #[inline] pub const fn from_bits(bits: $ty) -> Self { Self(bits) }

            /// Default constructor obeying reserved rules:
            /// - [res1] bits are set to 1
            /// - [res0] bits are set to 0
            #[inline] pub const fn new() -> Self { Self(Self::__RES1_MASK) }

            // --- Raw I/O ------------------------------------------------------
            /// Returns bits **with res0/res1 policy applied**.
            #[inline] pub const fn bits(self) -> $ty {
                (self.0 & !Self::__RES0_MASK) | Self::__RES1_MASK
            }

            /// Replace raw bits (builder style).
            #[inline] pub const fn with_bits(mut self, bits: $ty) -> Self { self.0 = bits; self }

            // --- Type-level field API ----------------------------------------
            /// Generic getter via a value-level field marker.
            pub fn get<F>(&self, _f: F) -> $ty
            where
                F: $crate::bitflags::FieldSpec<$Name>,
            {
                let off = F::OFF; let sz = F::SZ;
                let bits = (core::mem::size_of::<$ty>() as u32) * 8;
                debug_assert!(sz > 0 && off < bits && off + sz <= bits, "bitregs:get: out-of-range field");
                let val: $ty = if sz >= bits { !0 as $ty } else { ((1 as $ty) << sz) - (1 as $ty) };
                (self.0 >> off) & val
            }

            /// Generic setter via a value-level field marker (builder style).
            pub fn set<F>(mut self, _f: F, v: $ty) -> Self
            where
                F: $crate::bitflags::FieldSpec<$Name>,
            {
                let off = F::OFF; let sz = F::SZ;
                let bits = (core::mem::size_of::<$ty>() as u32) * 8;
                debug_assert!(sz > 0 && off < bits && off + sz <= bits, "bitregs:set: out-of-range field");
                let val: $ty = if sz >= bits { !0 as $ty } else { ((1 as $ty) << sz) - (1 as $ty) };
                debug_assert!((v & !val) == (0 as $ty), "bitregs:set: value has bits outside the field");
                let mask: $ty = val << off;
                self.0 = (self.0 & !mask) | ((v & val) << off);
                self
            }

            /// Generic getter via a value-level field marker with raw value.
            pub fn get_raw<F>(&self, _f: F) -> $ty
            where
                F: $crate::bitflags::FieldSpec<$Name>,
            {
                let off = F::OFF; let sz = F::SZ;
                let bits = (core::mem::size_of::<$ty>() as u32) * 8;
                debug_assert!(sz > 0 && off < bits && off + sz <= bits, "bitregs:get_raw: out-of-range field");
                let val: $ty = if sz >= bits { !0 as $ty } else { ((1 as $ty) << sz) - (1 as $ty) };
                let mask: $ty = val << off;
                self.0 & mask
            }

            /// Generic setter via a value-level field marker (builder style) with raw value.
            pub fn set_raw<F>(mut self, _f: F, v: $ty) -> Self
            where
                F: $crate::bitflags::FieldSpec<$Name>,
            {
                let off = F::OFF; let sz = F::SZ;
                let bits = (core::mem::size_of::<$ty>() as u32) * 8;
                debug_assert!(sz > 0 && off < bits && off + sz <= bits, "bitregs:set_raw: out-of-range field");
                let val: $ty = if sz >= bits { !0 as $ty } else { ((1 as $ty) << sz) - (1 as $ty) };
                let mask: $ty = val << off;

                debug_assert!((v & !mask) == (0 as $ty), "bitregs:set_raw: value has bits outside the field");

                self.0 = (self.0 & !mask) | (v & mask);
                self
            }

            /// Enum getter (returns `Option<Enum>`).
            pub fn get_enum<F, E>(&self, _f: F) -> Option<E>
            where
                F: $crate::bitflags::FieldSpec<$Name>,
                E: ::core::convert::TryFrom<$ty>,
            { ::core::convert::TryFrom::try_from(self.get(_f)).ok() }

            /// Enum setter (builder style).
            pub fn set_enum<F, E>(mut self, _f: F, e: E) -> Self
            where
                F: $crate::bitflags::FieldSpec<$Name>,
                E: Copy + Into<$ty>,
            { self = self.set(_f, e.into()); self }
        }

        impl ::core::default::Default for $Name {
            #[inline] fn default() -> Self { Self::new() }
        }

        // --- Expand fields & reserved items ----------------------------------
        bitregs!{ @fields $Name : $ty ; $($body)* }

        // --- Reserved masks / coverage / overlap checks ----------------------
        impl $Name {
            /// Mask of all [res0] bits (forced to 0 by `bits()`/`new()`).
            const __RES0_MASK: $ty = bitregs!{@collect_res<$ty> res0; 0 as $ty; $($body)*};
            /// Mask of all [res1] bits (forced to 1 by `bits()`/`new()`).
            const __RES1_MASK: $ty = bitregs!{@collect_res<$ty> res1; 0 as $ty; $($body)*};

            /// Union of all declared ranges (fields + reserved).
            const __DECLARED_MASK: $ty = bitregs!{@collect_mask<$ty>; 0 as $ty; $($body)*};

            /// Overlap mask: OR of pairwise intersections while folding.
            const __OVERLAP_MASK: $ty = bitregs!{@collect_overlap<$ty>; 0 as $ty; 0 as $ty; $($body)*};
        }

        // Full coverage assert
        const _: () = {
            let full: $ty = !0 as $ty;
            let covered_all = $Name::__DECLARED_MASK == full;
            let _ = [()][(!covered_all) as usize]; // compile error if not fully covered
        };
        // No-overlap assert
        const _: () = {
            let no_overlap = $Name::__OVERLAP_MASK == (0 as $ty);
            let _ = [()][(!no_overlap) as usize]; // compile error if any region overlaps
        };

        // Simple Debug
        impl ::core::fmt::Debug for $Name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, concat!(stringify!($Name), "({:#x})"), self.0)
            }
        }
    };

    (@assert_resattr res0) => {};
    (@assert_resattr res1) => {};
    (@assert_resattr ignore) => {};
    (@assert_resattr $other:ident) => {
        compile_error!("bitregs: reserved attribute must be one of [res0|res1|ignore]");
    };

    // =========================
    // Field/Reserved expansion
    // =========================

    (@fields $Name:ident : $ty:ty ; ) => {};

    // ---- union @[MSB:LSB]
    (@fields $Name:ident : $ty:ty ;
        union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($views:tt)* } , $($rest:tt)*
    ) => {
        bitregs!{ @fields $Name : $ty ;
            union $Union ( ($lsb) , (($msb) - ($lsb) + 1) ) { $($views)* },
            $($rest)*
        }
    };
    (@fields $Name:ident : $ty:ty ;
        union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($views:tt)* }
    ) => {
        bitregs!{ @fields $Name : $ty ;
            union $Union ( ($lsb) , (($msb) - ($lsb) + 1) ) { $($views)* }
        }
    };

    (@fields $Name:ident : $ty:ty ;
        union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($views:tt)* } $($rest:tt)+
    ) => {
        bitregs!{ @fields $Name : $ty ;
            union $Union ( ($lsb) , (($msb) - ($lsb) + 1) ) { $($views)* },
            $($rest)+
        }
    };

    // ---- union (off, sz)
    (@fields $Name:ident : $ty:ty ;
        union $Union:ident ( $off:expr , $sz:expr ) { $($views:tt)* } , $($rest:tt)*
    ) => {
        bitregs!{@union $Name : $ty ; $Union ; ($off) ; ($sz) ; { $($views)* }}
        bitregs!{ @fields $Name : $ty ; $($rest)* }
    };
    (@fields $Name:ident : $ty:ty ;
        union $Union:ident ( $off:expr , $sz:expr ) { $($views:tt)* }
    ) => {
        bitregs!{@union $Name : $ty ; $Union ; ($off) ; ($sz) ; { $($views)* }}
    };
    (@fields $Name:ident : $ty:ty ;
        union $Union:ident ( $off:expr , $sz:expr ) { $($views:tt)* } $($rest:tt)+
    ) => {
        bitregs!{@union $Name : $ty ; $Union ; ($off) ; ($sz) ; { $($views)* }}
        bitregs!{ @fields $Name : $ty ; $($rest)+ }
    };

    // ---- reserved @[MSB:LSB] → normalized (off, sz)
    (@fields $Name:ident : $ty:ty ;
        reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ] , $($rest:tt)*
    ) => {
        bitregs!{ @fields $Name : $ty ;
            reserved ( ($lsb) , (($msb) - ($lsb) + 1) ) [ $attr ],
            $($rest)*
        }
    };
    (@fields $Name:ident : $ty:ty ;
        reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ]
    ) => {
        bitregs!{ @fields $Name : $ty ;
            reserved ( ($lsb) , (($msb) - ($lsb) + 1) ) [ $attr ],
        }
    };

    // ---- reserved (off, sz)
    (@fields $Name:ident : $ty:ty ;
        reserved ( $off:expr , $sz:expr ) [ $attr:ident ] , $($rest:tt)*
    ) => {
        const _: () = {
            let bits = (core::mem::size_of::<$ty>() as u32) * 8;
            let off = $off as u32; let sz = $sz as u32;
            let cond = sz > 0 && off < bits && off + sz <= bits;
            let _ = [()][(!cond) as usize];
        };
        bitregs!{ @fields $Name : $ty ; $($rest)* }
    };
    (@fields $Name:ident : $ty:ty ;
        reserved ( $off:expr , $sz:expr ) [ $attr:ident ]
    ) => {
        const _: () = {
            let bits = (core::mem::size_of::<$ty>() as u32) * 8;
            let off = $off as u32; let sz = $sz as u32;
            let cond = sz > 0 && off < bits && off + sz <= bits;
            let _ = [()][(!cond) as usize];
        };
    };

    // ---- plain field @[MSB:LSB]
    (@fields $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] , $($rest:tt)*
    ) => {
        bitregs!{@field_emit_plain $Name : $ty ; $fvis $Field ; ($lsb) ; (($msb) - ($lsb) + 1)}
        bitregs!{ @fields $Name : $ty ; $($rest)* }
    };
    (@fields $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ]
    ) => {
        bitregs!{@field_emit_plain $Name : $ty ; $fvis $Field ; ($lsb) ; (($msb) - ($lsb) + 1)}
    };

    // ---- enum field @[MSB:LSB]
    (@fields $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] as $E:ident
        { $($V:ident = $val:expr),+ $(,)? } , $($rest:tt)*
    ) => {
        bitregs!{@field_emit_enum $Name : $ty ; $fvis $Field ; $E ; ($lsb) ; (($msb) - ($lsb) + 1) ; { $($V = $val),+ }}
        bitregs!{ @fields $Name : $ty ; $($rest)* }
    };
    // ---- enum field @[MSB:LSB]
    (@fields $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] as $E:ident
        { $($V:ident = $val:expr),+ $(,)? }
    ) => {
        bitregs!{@field_emit_enum $Name : $ty ; $fvis $Field ; $E ; ($lsb) ; (($msb) - ($lsb) + 1) ; { $($V = $val),+ }}
    };
    (@fields $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] as $E:ident [ $acc:ident ]
        { $($V:ident = $val:expr),+ $(,)? }
    ) => { compile_error!("bitregs: access qualifiers like [rw]/[ro]/[w]/[r]/[wo] are not supported; remove the [...]"); };

    // ---- plain field (off, sz)
    (@fields $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr ) , $($rest:tt)*
    ) => { compile_error!("bitregs: field layout must use @[MSB:LSB]"); };
    (@fields $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr )
    ) => { compile_error!("bitregs: field layout must use @[MSB:LSB]"); };
    (@fields $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr ) as $E:ident { $($V:ident = $val:expr),+ $(,)? } , $($rest:tt)*
    ) => { compile_error!("bitregs: field layout must use @[MSB:LSB]"); };
    (@fields $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr ) as $E:ident { $($V:ident = $val:expr),+ $(,)? }
    ) => { compile_error!("bitregs: field layout must use @[MSB:LSB]"); };
    (@fields $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr ) [ $acc:ident ]
    ) => { compile_error!("bitregs: access qualifiers are not supported; remove the [...]"); };

    (@field_emit_plain $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident ; $off:expr ; $sz:expr
    ) => {
        impl $Name {
            /// Value-level field marker (associated const)
            #[allow(non_upper_case_globals)]
            $fvis const $Field:
                $crate::bitflags::Field<$Name, { (($off) as u32) }, { (($sz) as u32) }> =
                $crate::bitflags::Field::<$Name, { (($off) as u32) }, { (($sz) as u32) }>::new();
        }
        const _: () = {
            let bits = (core::mem::size_of::<$ty>() as u32) * 8;
            let off = ($off) as u32; let sz = ($sz) as u32;
            let cond = sz > 0 && off < bits && off + sz <= bits;
            let _ = [()][(!cond) as usize];
        };
    };

    (@field_emit_enum $Name:ident : $ty:ty ;
        $fvis:vis $Field:ident ; $E:ident ; $off:expr ; $sz:expr ; { $($V:ident = $val:expr),+ }
    ) => {
        #[repr(u128)]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
        $fvis enum $E { $( $V = $val ),+ }
        impl From<$E> for $ty { fn from(e: $E) -> $ty { e as u128 as $ty } }
        impl ::core::convert::TryFrom<$ty> for $E {
            type Error = ();
            fn try_from(x: $ty) -> Result<Self, ()> {
                match x as u128 { $( v if v == $E::$V as u128 => Ok($E::$V), )+ _ => Err(()) }
            }
        }
        const _: () = {
            let sz = ($sz) as u32;
            let vmax = if sz >= 128 { u128::MAX } else { (1u128 << sz) - 1 };
            $( { let cond = ($val as u128) <= vmax; let _ = [()][(!cond) as usize]; } )+
        };

        bitregs!{@field_emit_plain $Name : $ty ; $fvis $Field ; $off ; $sz}
    };

    // =========================
    // Union expansion helpers
    // =========================

    (@union $Name:ident : $ty:ty ; $Union:ident ; $off:expr ; $sz:expr ; { $($views:tt)* }) => {
        const _: () = {
            let bits = (core::mem::size_of::<$ty>() as u32) * 8;
            let off = $off as u32; let sz = $sz as u32;
            let cond = sz > 0 && off < bits && off + sz <= bits;
            let _ = [()][(!cond) as usize];
        };

        impl $Name {
            #[allow(non_upper_case_globals)]
            pub const $Union:
                $crate::bitflags::Field<$Name, { ($off as u32) }, { ($sz as u32) }> =
                $crate::bitflags::Field::<$Name, { ($off as u32) }, { ($sz as u32) }>::new();
        }

        bitregs!{@union_views $Name : $ty ; $Union ; ($off as u32) ; ($sz as u32) ; $($views)* }
    };

    (@union $Name:ident : $ty:ty ; $Union:ident ; $off:expr ; $sz:expr ; ) => {
        const _: () = {
            let bits = (core::mem::size_of::<$ty>() as u32) * 8;
            let off = $off as u32; let sz = $sz as u32;
            let cond = sz > 0 && off < bits && off + sz <= bits;
            let _ = [()][(!cond) as usize];
        };

        impl $Name {
            #[allow(non_upper_case_globals)]
            pub const $Union:
                $crate::bitflags::Field<$Name, { ($off as u32) }, { ($sz as u32) }> =
                $crate::bitflags::Field::<$Name, { ($off as u32) }, { ($sz as u32) }>::new();
        }
    };

    (@union_views $Name:ident : $ty:ty ; $Union:ident ; $base_off:expr ; $base_sz:expr ; ) => {};
    (@union_views $Name:ident : $ty:ty ; $Union:ident ; $base_off:expr ; $base_sz:expr ;
        view $View:ident { $($body:tt)* } , $($rest:tt)*
    ) => {
        bitregs!{@union_view $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ; { $($body)* }}
        bitregs!{@union_views $Name : $ty ; $Union ; $base_off ; $base_sz ; $($rest)*}
    };
    (@union_views $Name:ident : $ty:ty ; $Union:ident ; $base_off:expr ; $base_sz:expr ;
        view $View:ident { $($body:tt)* }
    ) => {
        bitregs!{@union_view $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ; { $($body)* }}
    };
    (@union_views $Name:ident : $ty:ty ; $Union:ident ; $base_off:expr ; $base_sz:expr ;
        view $View:ident { $($body:tt)* } $($rest:tt)+
    ) => {
        bitregs!{@union_view $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ; { $($body)* }}
        bitregs!{@union_views $Name : $ty ; $Union ; $base_off ; $base_sz ; $($rest)+}
    };

    (@union_view $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ; { $($body:tt)* }) => {
        bitregs!{@union_view_fields $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ; $($body)* }

        const _: () = {
            let view_mask: $ty = $crate::__bitregs_internal_view_mask_fold!($ty, $base_off, $base_sz; $($body)*);
            let view_overlap: $ty = $crate::__bitregs_internal_view_overlap_fold!($ty, $base_off, $base_sz, 0 as $ty; $($body)*);
            let full_mask: $ty = {
                let bits = (core::mem::size_of::<$ty>() as u32) * 8;
                let off = $base_off as u32;
                let sz = $base_sz as u32;
                let local_mask = if sz >= bits { !0 as $ty } else { ((1 as $ty) << sz) - (1 as $ty) };
                local_mask << off
            };
            // Compile-time guard: the view must cover the union span without overlaps
            let _ = [()][(!(view_mask == full_mask)) as usize];
            let _ = [()][(!(view_overlap == (0 as $ty))) as usize];
        };
    };

    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ; ) => {};

    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ] , $($rest:tt)*
    ) => {
        bitregs!{@union_view_fields $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ;
            reserved(
                (bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ,
                (($msb) - ($lsb) + 1)
            )[ $attr ],
            $($rest)*
        }
    };
    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ]
    ) => {
        bitregs!{@union_view_fields $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ;
            reserved(
                (bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ,
                (($msb) - ($lsb) + 1)
            )[ $attr ]
        }
    };

    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        reserved ( $off:expr , $sz:expr ) [ $attr:ident ] , $($rest:tt)*
    ) => {
        const _: () = {
            let sz_total = $base_sz as u32;
            let off = $off as u32; let sz = $sz as u32;
            let cond = sz > 0 && off < sz_total && off + sz <= sz_total;
            let _ = [()][(!cond) as usize];
        };
        bitregs!{@union_view_fields $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ; $($rest)* }
    };
    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        reserved ( $off:expr , $sz:expr ) [ $attr:ident ]
    ) => {
        const _: () = {
            let sz_total = $base_sz as u32;
            let off = $off as u32; let sz = $sz as u32;
            let cond = sz > 0 && off < sz_total && off + sz <= sz_total;
            let _ = [()][(!cond) as usize];
        };
    };

    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] , $($rest:tt)*
    ) => {
        bitregs!{@union_view_field_emit_plain $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ;
            $fvis $Field ;
            (bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ;
            (($msb) - ($lsb) + 1)
        }
        bitregs!{@union_view_fields $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ; $($rest)* }
    };
    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ]
    ) => {
        bitregs!{@union_view_field_emit_plain $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ;
            $fvis $Field ;
            (bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ;
            (($msb) - ($lsb) + 1)
        }
    };

    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] as $E:ident
        { $($V:ident = $val:expr),+ $(,)? } , $($rest:tt)*
    ) => {
        bitregs!{@union_view_field_emit_enum $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ;
            $fvis $Field ; $E ;
            (bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ;
            (($msb) - ($lsb) + 1) ; { $($V = $val),+ }
        }
        bitregs!{@union_view_fields $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ; $($rest)* }
    };
    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] as $E:ident
        { $($V:ident = $val:expr),+ $(,)? }
    ) => {
        bitregs!{@union_view_field_emit_enum $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ;
            $fvis $Field ; $E ;
            (bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ;
            (($msb) - ($lsb) + 1) ; { $($V = $val),+ }
        }
    };

    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] [ $acc:ident ] $(,)? $($rest:tt)*
    ) => { compile_error!("bitregs: access qualifiers are not supported inside union view; remove the [...]"); };

    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr ) , $($rest:tt)*
    ) => { compile_error!("bitregs: union view fields must use @[MSB:LSB] syntax"); };
    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr )
    ) => { compile_error!("bitregs: union view fields must use @[MSB:LSB] syntax"); };

    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident as $E:ident { $($body:tt)* } , $($rest:tt)*
    ) => { compile_error!("bitregs: union view fields must include @[MSB:LSB]"); };
    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident as $E:ident { $($body:tt)* }
    ) => { compile_error!("bitregs: union view fields must include @[MSB:LSB]"); };

    (@union_view_field_emit_plain $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident ; $off:expr ; $sz:expr
    ) => {
        impl $Name {
            #[allow(non_upper_case_globals)]
            $fvis const $Field:
                $crate::bitflags::Field<$Name, { (($base_off as u32) + ($off as u32)) }, { ($sz as u32) }> =
                $crate::bitflags::Field::<$Name, { (($base_off as u32) + ($off as u32)) }, { ($sz as u32) }>::new();
        }
        const _: () = {
            let sz_total = $base_sz as u32;
            let off = $off as u32; let sz = $sz as u32;
            let cond = sz > 0 && off < sz_total && off + sz <= sz_total;
            let _ = [()][(!cond) as usize];
        };
    };

    (@union_view_field_emit_enum $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident ; $E:ident ; $off:expr ; $sz:expr ; { $($V:ident = $val:expr),+ }
    ) => {
        #[repr(u128)]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
        $fvis enum $E { $( $V = $val ),+ }
        impl From<$E> for $ty { fn from(e: $E) -> $ty { e as u128 as $ty } }
        impl ::core::convert::TryFrom<$ty> for $E {
            type Error = ();
            fn try_from(x: $ty) -> Result<Self, ()> {
                match x as u128 { $( v if v == $E::$V as u128 => Ok($E::$V), )+ _ => Err(()) }
            }
        }
        const _: () = {
            let sz = $sz as u32;
            let vmax = if sz >= 128 { u128::MAX } else { (1u128 << sz) - 1 };
            $( { let cond = ($val as u128) <= vmax; let _ = [()][(!cond) as usize]; } )+
        };

        bitregs!{@union_view_field_emit_plain $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ;
            $fvis $Field ; $off ; $sz
        }
    };

    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] as $E:ident [ $acc:ident ] { $($body:tt)* } $(,)? $($rest:tt)*
    ) => { compile_error!("bitregs: access qualifiers are not supported inside union view; remove the [...]"); };

    // =========================
    // Helpers: masks & folding
    // =========================

    // Build a mask (typed) from (off, sz)
    (@mask<$ty:ty> ($off:expr, $sz:expr)) => {{
        let bits = (core::mem::size_of::<$ty>() as u32) * 8;
        ((if ($sz as u32) >= bits { !0 as $ty } else { ((1 as $ty) << ($sz as u32)) - (1 as $ty) }) << ($off as u32))
    }};

    // View mask helper (offset relative to union base)
    (@view_mask<$ty:ty> $base_off:expr; ($off:expr, $sz:expr)) => {{
        let bits = (core::mem::size_of::<$ty>() as u32) * 8;
        let base = $base_off as u32;
        let off = $off as u32;
        let sz = $sz as u32;
        ((if sz >= bits { !0 as $ty } else { ((1 as $ty) << sz) - (1 as $ty) }) << (base + off))
    }};

    // Translate an absolute bit offset into the union-local offset.
    (@union_local_off $base_off:expr ; $base_sz:expr ; $abs_off:expr) => {{
        let base = $base_off as u32;
        let span = $base_sz as u32;
        let abs = $abs_off as u32;
        let cond = abs >= base && abs < base + span;
        let _ = [()][(!cond) as usize];
        abs - base
    }};

    // Reserved mask collectors (for res0/res1)
    (@collect_res<$ty:ty> $k:ident; $acc:expr; ) => { $acc };
    (@collect_res<$ty:ty> res0; $acc:expr; reserved ( $off:expr , $sz:expr ) [ res0 ] , $($rest:tt)* ) => {
        bitregs!{@collect_res<$ty> res0; ($acc | bitregs!{@mask<$ty>($off,$sz)}); $($rest)*}
    };
    (@collect_res<$ty:ty> res0; $acc:expr; reserved ( $off:expr , $sz:expr ) [ res0 ] ) => { ($acc | bitregs!{@mask<$ty>($off,$sz)}) };
    (@collect_res<$ty:ty> res1; $acc:expr; reserved ( $off:expr , $sz:expr ) [ res1 ] , $($rest:tt)* ) => {
        bitregs!{@collect_res<$ty> res1; ($acc | bitregs!{@mask<$ty>($off,$sz)}); $($rest)*}
    };
    (@collect_res<$ty:ty> res1; $acc:expr; reserved ( $off:expr , $sz:expr ) [ res1 ] ) => { ($acc | bitregs!{@mask<$ty>($off,$sz)}) };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; reserved ( $off:expr , $sz:expr ) [ ignore ] , $($rest:tt)* ) => {
        bitregs!{@collect_res<$ty> $k; $acc; $($rest)*}
    };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; reserved ( $off:expr , $sz:expr ) [ ignore ] ) => { $acc };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ] , $($rest:tt)* ) => {
        bitregs!{@collect_res<$ty> $k; $acc; reserved( ($lsb), (($msb)-($lsb)+1) )[ $attr ], $($rest)*}
    };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ] ) => {
        bitregs!{@collect_res<$ty> $k; $acc; reserved( ($lsb), (($msb)-($lsb)+1) )[ $attr ],}
    };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($body:tt)* } , $($rest:tt)* ) => {
        bitregs!{@collect_res<$ty> $k; $acc; $($rest)*}
    };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($body:tt)* } ) => { $acc };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; union $Union:ident ( $off:expr , $sz:expr ) { $($body:tt)* } , $($rest:tt)* ) => {
        bitregs!{@collect_res<$ty> $k; $acc; $($rest)*}
    };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; union $Union:ident ( $off:expr , $sz:expr ) { $($body:tt)* } ) => { $acc };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; $other:tt , $($rest:tt)* ) => {
        bitregs!{@collect_res<$ty> $k; $acc; $($rest)*}
    };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; $other:tt $($rest:tt)+ ) => {
        bitregs!{@collect_res<$ty> $k; $acc; $($rest)*}
    };
    (@collect_res<$ty:ty> $k:ident; $acc:expr; $other:tt ) => { $acc };

    // Coverage collector (union of all ranges)
    (@collect_mask<$ty:ty>; $acc:expr; ) => { $acc };
    (@collect_mask<$ty:ty>; $acc:expr; reserved ( $off:expr , $sz:expr ) [ $attr:ident ] , $($rest:tt)* ) => {
        bitregs!{@collect_mask<$ty>; ($acc | bitregs!{@mask<$ty>($off,$sz)}); $($rest)*}
    };
    (@collect_mask<$ty:ty>; $acc:expr; reserved ( $off:expr , $sz:expr ) [ $attr:ident ] ) => { ($acc | bitregs!{@mask<$ty>($off,$sz)}) };
    (@collect_mask<$ty:ty>; $acc:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) , $($rest:tt)* ) => {
        bitregs!{@collect_mask<$ty>; ($acc | bitregs!{@mask<$ty>($off,$sz)}); $($rest)*}
    };
    (@collect_mask<$ty:ty>; $acc:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) ) => {
        ($acc | bitregs!{@mask<$ty>($off,$sz)})
    };
    (@collect_mask<$ty:ty>; $acc:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) as $E:ident { $($V:ident = $val:expr),+ $(,)? } , $($rest:tt)* ) => {
        bitregs!{@collect_mask<$ty>; ($acc | bitregs!{@mask<$ty>($off,$sz)}); $($rest)*}
    };
    (@collect_mask<$ty:ty>; $acc:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) as $E:ident { $($V:ident = $val:expr),+ $(,)? } ) => {
        ($acc | bitregs!{@mask<$ty>($off,$sz)})
    };
    (@collect_mask<$ty:ty>; $acc:expr; $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] $( $tail:tt )* ) => {
        bitregs!{@collect_mask<$ty>; $acc; $fvis $Field ( ($lsb), (($msb)-($lsb)+1) ) $( $tail )*}
    };
    (@collect_mask<$ty:ty>; $acc:expr; reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ] $(,)? $($rest:tt)* ) => {
        bitregs!{@collect_mask<$ty>; $acc; reserved( ($lsb), (($msb)-($lsb)+1) )[ $attr ], $($rest)*}
    };
    (@collect_mask<$ty:ty>; $acc:expr; union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($body:tt)* } , $($rest:tt)* ) => {
        bitregs!{@collect_mask<$ty>; ($acc | bitregs!{@mask<$ty>($lsb, (($msb)-($lsb)+1))}); $($rest)*}
    };
    (@collect_mask<$ty:ty>; $acc:expr; union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($body:tt)* } ) => {
        ($acc | bitregs!{@mask<$ty>($lsb, (($msb)-($lsb)+1))})
    };
    (@collect_mask<$ty:ty>; $acc:expr; union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($body:tt)* } $($rest:tt)+ ) => {
        bitregs!{@collect_mask<$ty>; ($acc | bitregs!{@mask<$ty>($lsb, (($msb)-($lsb)+1))}); $($rest)+}
    };
    (@collect_mask<$ty:ty>; $acc:expr; union $Union:ident ( $off:expr , $sz:expr ) { $($body:tt)* } , $($rest:tt)* ) => {
        bitregs!{@collect_mask<$ty>; ($acc | bitregs!{@mask<$ty>($off,$sz)}); $($rest)*}
    };
    (@collect_mask<$ty:ty>; $acc:expr; union $Union:ident ( $off:expr , $sz:expr ) { $($body:tt)* } ) => {
        ($acc | bitregs!{@mask<$ty>($off,$sz)})
    };
    (@collect_mask<$ty:ty>; $acc:expr; union $Union:ident ( $off:expr , $sz:expr ) { $($body:tt)* } $($rest:tt)+ ) => {
        bitregs!{@collect_mask<$ty>; ($acc | bitregs!{@mask<$ty>($off,$sz)}); $($rest)+}
    };
    (@collect_mask<$ty:ty>; $acc:expr; $other:tt , $($rest:tt)* ) => {
        bitregs!{@collect_mask<$ty>; $acc; $($rest)*}
    };
    (@collect_mask<$ty:ty>; $acc:expr; $other:tt $($rest:tt)+ ) => {
        bitregs!{@collect_mask<$ty>; $acc; $($rest)*}
    };
    (@collect_mask<$ty:ty>; $acc:expr; $other:tt ) => { $acc };

    // Overlap collector (fold with running union & overlap)
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr; ) => { $oacc };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        reserved ( $off:expr , $sz:expr ) [ $attr:ident ] , $($rest:tt)*
    ) => {
        {
        bitregs!{@collect_overlap<$ty>;
            ($uacc | bitregs!{@mask<$ty>($off,$sz)});
            ($oacc | ($uacc & bitregs!{@mask<$ty>($off,$sz)}));
            $($rest)*}
        };
    };

    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident as $E:ident { $($V:ident = $val:expr),+ $(,)? } , $($rest:tt)*
    ) => {
        bitregs!{@union_view_fields $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ;
            $fvis $Field ( 0 , $base_sz ) as $E { $($V = $val),+ },
            $($rest)*
        }
    };
    (@union_view_fields $Name:ident : $ty:ty ; $Union:ident ; $View:ident ; $base_off:expr ; $base_sz:expr ;
        $fvis:vis $Field:ident as $E:ident { $($V:ident = $val:expr),+ $(,)? }
    ) => {
        bitregs!{@union_view_fields $Name : $ty ; $Union ; $View ; $base_off ; $base_sz ;
            $fvis $Field ( 0 , $base_sz ) as $E { $($V = $val),+ }
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        reserved ( $off:expr , $sz:expr ) [ $attr:ident ]
    ) => {
        {
            ($oacc | ($uacc & bitregs!{@mask<$ty>($off,$sz)}))
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr ) [ $accs:ident ] , $($rest:tt)*
    ) => {
        {
            bitregs!{@collect_overlap<$ty>;
                ($uacc | bitregs!{@mask<$ty>($off,$sz)});
                ($oacc | ($uacc & bitregs!{@mask<$ty>($off,$sz)}));
                $($rest)*
            }
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr ) [ $accs:ident ]
    ) => {
        {
            ($oacc | ($uacc & bitregs!{@mask<$ty>($off,$sz)}))
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr ) as $E:ident [ $accs:ident ] { $($V:ident = $val:expr),+ $(,)? } , $($rest:tt)*
    ) => {
        {
            bitregs!{@collect_overlap<$ty>;
                ($uacc | bitregs!{@mask<$ty>($off,$sz)});
                ($oacc | ($uacc & bitregs!{@mask<$ty>($off,$sz)}));
                $($rest)*
            }
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        $fvis:vis $Field:ident ( $off:expr , $sz:expr ) as $E:ident [ $accs:ident ] { $($V:ident = $val:expr),+ $(,)? }
    ) => {
        {
            ($oacc | ($uacc & bitregs!{@mask<$ty>($off,$sz)}))
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] $( $tail:tt )*
    ) => {
        bitregs!{@collect_overlap<$ty>; $uacc; $oacc; $fvis $Field ( ($lsb), (($msb)-($lsb)+1) ) $( $tail )*}
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ] $(,)? $($rest:tt)*
    ) => {
        bitregs!{@collect_overlap<$ty>; $uacc; $oacc; reserved( ($lsb), (($msb)-($lsb)+1) )[ $attr ], $($rest)*}
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($body:tt)* } , $($rest:tt)*
    ) => {
        {
            bitregs!{@collect_overlap<$ty>;
                ($uacc | bitregs!{@mask<$ty>($lsb, (($msb)-($lsb)+1))});
                ($oacc | ($uacc & bitregs!{@mask<$ty>($lsb, (($msb)-($lsb)+1))}));
                $($rest)*
            }
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($body:tt)* }
    ) => {
        {
            ($oacc | ($uacc & bitregs!{@mask<$ty>($lsb, (($msb)-($lsb)+1))}))
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        union $Union:ident @ [ $msb:tt : $lsb:tt ] { $($body:tt)* } $($rest:tt)+
    ) => {
        {
            bitregs!{@collect_overlap<$ty>;
                ($uacc | bitregs!{@mask<$ty>($lsb, (($msb)-($lsb)+1))});
                ($oacc | ($uacc & bitregs!{@mask<$ty>($lsb, (($msb)-($lsb)+1))}));
                $($rest)+
            }
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        union $Union:ident ( $off:expr , $sz:expr ) { $($body:tt)* } , $($rest:tt)*
    ) => {
        {
            bitregs!{@collect_overlap<$ty>;
                ($uacc | bitregs!{@mask<$ty>($off,$sz)});
                ($oacc | ($uacc & bitregs!{@mask<$ty>($off,$sz)}));
                $($rest)*
            }
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        union $Union:ident ( $off:expr , $sz:expr ) { $($body:tt)* }
    ) => {
        {
            ($oacc | ($uacc & bitregs!{@mask<$ty>($off,$sz)}))
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr;
        union $Union:ident ( $off:expr , $sz:expr ) { $($body:tt)* } $($rest:tt)+
    ) => {
        {
            bitregs!{@collect_overlap<$ty>;
                ($uacc | bitregs!{@mask<$ty>($off,$sz)});
                ($oacc | ($uacc & bitregs!{@mask<$ty>($off,$sz)}));
                $($rest)+
            }
        }
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr; $other:tt , $($rest:tt)* ) => {
        bitregs!{@collect_overlap<$ty>; $uacc; $oacc; $($rest)*}
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr; $other:tt $($rest:tt)+ ) => {
        bitregs!{@collect_overlap<$ty>; $uacc; $oacc; $($rest)*}
    };
    (@collect_overlap<$ty:ty>; $uacc:expr; $oacc:expr; $other:tt ) => { $oacc };
}

// =========================
// Helpers for union views
// =========================

#[doc(hidden)]
#[macro_export]
macro_rules! __bitregs_internal_view_mask_fold {
    ($ty:ty, $base_off:expr, $base_sz:expr; ) => { 0 as $ty };
    ($ty:ty, $base_off:expr, $base_sz:expr; reserved ( $off:expr , $sz:expr ) [ $attr:ident ] , $($rest:tt)* ) => {
        $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)}
            | $crate::__bitregs_internal_view_mask_fold!($ty, $base_off, $base_sz; $($rest)*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; reserved ( $off:expr , $sz:expr ) [ $attr:ident ] ) => {
        $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)}
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ] , $($rest:tt)* ) => {
        $crate::__bitregs_internal_view_mask_fold!($ty, $base_off, $base_sz;
            reserved(
                ($crate::bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ,
                (($msb)-($lsb)+1)
            )[ $attr ], $($rest)*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ] ) => {
        $crate::__bitregs_internal_view_mask_fold!($ty, $base_off, $base_sz;
            reserved(
                ($crate::bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ,
                (($msb)-($lsb)+1)
            )[ $attr ])
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) , $($rest:tt)* ) => {
        $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)}
            | $crate::__bitregs_internal_view_mask_fold!($ty, $base_off, $base_sz; $($rest)*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) ) => {
        $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)}
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) as $E:ident { $($V:ident = $val:expr),+ $(,)? } , $($rest:tt)* ) => {
        $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)}
            | $crate::__bitregs_internal_view_mask_fold!($ty, $base_off, $base_sz; $($rest)*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) as $E:ident { $($V:ident = $val:expr),+ $(,)? } ) => {
        $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)}
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] $( $tail:tt )* ) => {
        $crate::__bitregs_internal_view_mask_fold!($ty, $base_off, $base_sz;
            $fvis $Field (
                ($crate::bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ,
                (($msb)-($lsb)+1)
            ) $( $tail )*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; $fvis:vis $Field:ident as $E:ident { $($V:ident = $val:expr),+ $(,)? } , $($rest:tt)* ) => {
        $crate::bitregs!{@view_mask<$ty> $base_off; (0, $base_sz)}
            | $crate::__bitregs_internal_view_mask_fold!($ty, $base_off, $base_sz; $($rest)*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; $fvis:vis $Field:ident as $E:ident { $($V:ident = $val:expr),+ $(,)? } ) => {
        $crate::bitregs!{@view_mask<$ty> $base_off; (0, $base_sz)}
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; $other:tt , $($rest:tt)* ) => {
        $crate::__bitregs_internal_view_mask_fold!($ty, $base_off, $base_sz; $($rest)*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; $other:tt $($rest:tt)+ ) => {
        $crate::__bitregs_internal_view_mask_fold!($ty, $base_off, $base_sz; $($rest)*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr; $other:tt ) => { 0 as $ty };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __bitregs_internal_view_overlap_fold {
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; ) => { 0 as $ty };
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; reserved ( $off:expr , $sz:expr ) [ $attr:ident ] , $($rest:tt)* ) => {{
        let mask = $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)};
        ( ($running & mask)
            | $crate::__bitregs_internal_view_overlap_fold!($ty, $base_off, $base_sz, ($running | mask); $($rest)*) )
    }};
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; reserved ( $off:expr , $sz:expr ) [ $attr:ident ] ) => {{
        let mask = $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)};
        $running & mask
    }};
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ] , $($rest:tt)* ) => {
        $crate::__bitregs_internal_view_overlap_fold!($ty, $base_off, $base_sz, $running;
            reserved(
                ($crate::bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ,
                (($msb)-($lsb)+1)
            )[ $attr ], $($rest)*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; reserved @ [ $msb:tt : $lsb:tt ] [ $attr:ident ] ) => {
        $crate::__bitregs_internal_view_overlap_fold!($ty, $base_off, $base_sz, $running;
            reserved(
                ($crate::bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ,
                (($msb)-($lsb)+1)
            )[ $attr ])
    };
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) , $($rest:tt)* ) => {{
        let mask = $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)};
        ( ($running & mask)
            | $crate::__bitregs_internal_view_overlap_fold!($ty, $base_off, $base_sz, ($running | mask); $($rest)*) )
    }};
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) ) => {{
        let mask = $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)};
        $running & mask
    }};
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) as $E:ident { $($V:ident = $val:expr),+ $(,)? } , $($rest:tt)* ) => {{
        let mask = $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)};
        ( ($running & mask)
            | $crate::__bitregs_internal_view_overlap_fold!($ty, $base_off, $base_sz, ($running | mask); $($rest)*) )
    }};
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; $fvis:vis $Field:ident ( $off:expr , $sz:expr ) as $E:ident { $($V:ident = $val:expr),+ $(,)? } ) => {{
        let mask = $crate::bitregs!{@view_mask<$ty> $base_off; ($off,$sz)};
        $running & mask
    }};
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; $fvis:vis $Field:ident @ [ $msb:tt : $lsb:tt ] $( $tail:tt )* ) => {
        $crate::__bitregs_internal_view_overlap_fold!($ty, $base_off, $base_sz, $running;
            $fvis $Field (
                ($crate::bitregs!{@union_local_off $base_off ; $base_sz ; ($lsb)}) ,
                (($msb)-($lsb)+1)
            ) $( $tail )*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; $fvis:vis $Field:ident as $E:ident { $($V:ident = $val:expr),+ $(,)? } , $($rest:tt)* ) => {{
        let mask = $crate::bitregs!{@view_mask<$ty> $base_off; (0, $base_sz)};
        ( ($running & mask)
            | $crate::__bitregs_internal_view_overlap_fold!($ty, $base_off, $base_sz, ($running | mask); $($rest)*) )
    }};
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; $fvis:vis $Field:ident as $E:ident { $($V:ident = $val:expr),+ $(,)? } ) => {{
        let mask = $crate::bitregs!{@view_mask<$ty> $base_off; (0, $base_sz)};
        $running & mask
    }};
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; $other:tt , $($rest:tt)* ) => {
        $crate::__bitregs_internal_view_overlap_fold!($ty, $base_off, $base_sz, $running; $($rest)*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; $other:tt $($rest:tt)+ ) => {
        $crate::__bitregs_internal_view_overlap_fold!($ty, $base_off, $base_sz, $running; $($rest)*)
    };
    ($ty:ty, $base_off:expr, $base_sz:expr, $running:expr; $other:tt ) => { 0 as $ty };
}

#[cfg(test)]
mod test {
    bitregs! {
        pub(super) struct Timer: u32 {
            pub period@[7:0],
            reserved@[15:8] [res0],
            pub enable@[16:16],
            reserved@[23:17] [ignore],
            reserved@[31:24] [res1],
        }
    }

    bitregs! {
        pub(super) struct Status: u16 {
            pub state@[2:0] as State {
                Idle = 0b000,
                Busy = 0b001,
                Done = 0b010,
                Fault = 0b011,
            },
            reserved@[7:3] [res0],
            pub error@[8:8],
            reserved@[13:9] [ignore],
            reserved@[15:14] [res1],
        }
    }

    bitregs! {
        pub(super) struct Packet: u16 {
            union hdr@[7:0] {
                view split {
                    pub lo@[3:0],
                    pub hi@[7:4],
                }
                view kind {
                    pub kind@[7:0] as Kind {
                        A = 0b0000_0001,
                        B = 0b0000_0010,
                        C = 0b0001_0000,
                        D = 0b0010_0000,
                    }
                }
                view flags {
                    pub enabled@[0:0],
                    reserved@[2:1] [res0],
                    pub err@[3:3],
                    reserved@[7:4] [ignore],
                }
            }

            reserved@[15:8] [res1],
        }
    }

    #[test]
    fn bitregs_applies_reserved_policies() {
        let reg = Timer::new().set(Timer::period, 0xAA).set(Timer::enable, 1);

        assert_eq!(reg.bits(), 0xFF01_00AA);
        assert_eq!(reg.get(Timer::period), 0xAA);
        assert_eq!(reg.get(Timer::enable), 1);
    }

    #[test]
    fn bitregs_enum_roundtrip() {
        let mut reg = Status::new().set_enum(Status::state, State::Done);

        assert_eq!(reg.get_enum(Status::state), Some(State::Done));
        assert_eq!(reg.bits() & 0xC000, 0xC000);
        assert_eq!(reg.bits() & 0x00F8, 0);

        reg = reg.with_bits(0x01FF);
        assert_eq!(reg.get(Status::error), 1);
        assert_eq!(reg.bits() & 0x00F8, 0);
    }

    #[test]
    fn bitregs_enum_invalid_pattern_returns_none() {
        let reg = Status::new().set(Status::state, 0b111);

        assert_eq!(reg.get_enum(Status::state), None::<State>);
    }

    #[test]
    fn bitregs_union_views_share_bits() {
        let reg = Packet::new().set(Packet::lo, 0x5).set(Packet::hi, 0xA);

        assert_eq!(reg.get(Packet::lo), 0x5);
        assert_eq!(reg.get(Packet::hi), 0xA);
        assert_eq!(reg.bits() & 0x00FF, 0xA5);

        let reg = Packet::new().set_enum(Packet::kind, Kind::C);
        assert_eq!(reg.get(Packet::hi), 0x1);
        assert_eq!(reg.get(Packet::lo), 0x0);
        assert_eq!(reg.get_enum(Packet::kind), Some(Kind::C));

        let reg = Packet::new().set(Packet::enabled, 1).set(Packet::err, 1);
        assert_eq!(reg.get(Packet::enabled), 1);
        assert_eq!(reg.get(Packet::err), 1);
        assert_eq!(reg.bits() & 0x000F, 0b1001);
    }
}
