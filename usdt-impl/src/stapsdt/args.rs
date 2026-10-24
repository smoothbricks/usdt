// Copyright 2024 Aapo Alasuutari
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Helpers for generating GNU Assembler format for use in STAPSDT probes.

use crate::target::Architecture;
use crate::DataType;
use dtrace_parser::{BitWidth, DataType as NativeDataType, Integer, Sign};

// Dispatch admits only 64-bit targets. Pointer-sized integers and addresses
// therefore have the target width, regardless of the generator's host width.
fn integer_to_asm_op(integer: &Integer, reg_index: usize, arch: Architecture) -> &'static str {
    assert!(
        reg_index < 6,
        "Up to 6 probe arguments are currently supported"
    );
    let registers = match arch {
        Architecture::X86_64 => match integer.width {
            BitWidth::Bit8 => ["%dil", "%sil", "%dl", "%cl", "%r8b", "%r9b"],
            BitWidth::Bit16 => ["%di", "%si", "%dx", "%cx", "%r8w", "%r9w"],
            BitWidth::Bit32 => ["%edi", "%esi", "%edx", "%ecx", "%r8d", "%r9d"],
            BitWidth::Bit64 | BitWidth::Pointer => ["%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"],
        },
        Architecture::Aarch64 => ["x0", "x1", "x2", "x3", "x4", "x5"],
    };
    registers[reg_index]
}

fn integer_to_arg_size(integer: &Integer) -> &'static str {
    match (integer.width, integer.sign) {
        (BitWidth::Bit8, Sign::Unsigned) => "1",
        (BitWidth::Bit8, _) => "-1",
        (BitWidth::Bit16, Sign::Unsigned) => "2",
        (BitWidth::Bit16, _) => "-2",
        (BitWidth::Bit32, Sign::Unsigned) => "4",
        (BitWidth::Bit32, _) => "-4",
        (BitWidth::Bit64 | BitWidth::Pointer, Sign::Unsigned) => "8",
        (BitWidth::Bit64 | BitWidth::Pointer, _) => "-8",
    }
}

const POINTER: Integer = Integer {
    sign: Sign::Unsigned,
    width: BitWidth::Pointer,
};
const UNIQUE_ID: Integer = Integer {
    sign: Sign::Unsigned,
    width: BitWidth::Bit64,
};

/// Format N@OP, where N is the signed byte width and OP the GNU assembler
/// operand, using the consuming target's ABI.
/// See https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
pub(crate) fn format_argument((reg_index, typ): (usize, &DataType), arch: Architecture) -> String {
    let (integer, dereference) = match typ {
        DataType::Native(NativeDataType::Integer(integer)) => (integer, false),
        DataType::Native(NativeDataType::Pointer(_)) => (&POINTER, true),
        DataType::Native(NativeDataType::String) | DataType::Serializable(_) => (&POINTER, false),
        DataType::UniqueId => (&UNIQUE_ID, false),
    };
    let size = integer_to_arg_size(integer);
    let operand = integer_to_asm_op(integer, reg_index, arch);
    if dereference {
        format!("{}@({})", size, operand)
    } else {
        format!("{}@{}", size, operand)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_both_target_abis_on_any_host() {
        for (width, sign, x86, arm) in [
            (BitWidth::Bit8, Sign::Unsigned, "1@%dil", "1@x0"),
            (BitWidth::Bit16, Sign::Signed, "-2@%di", "-2@x0"),
            (BitWidth::Bit32, Sign::Signed, "-4@%edi", "-4@x0"),
            (BitWidth::Bit64, Sign::Unsigned, "8@%rdi", "8@x0"),
            (BitWidth::Pointer, Sign::Signed, "-8@%rdi", "-8@x0"),
        ] {
            let typ = DataType::Native(NativeDataType::Integer(Integer { sign, width }));
            assert_eq!(format_argument((0, &typ), Architecture::X86_64), x86);
            assert_eq!(format_argument((0, &typ), Architecture::Aarch64), arm);
        }
        assert_eq!(
            format_argument((5, &DataType::UniqueId), Architecture::X86_64),
            "8@%r9"
        );
        assert_eq!(
            format_argument((5, &DataType::UniqueId), Architecture::Aarch64),
            "8@x5"
        );
    }
}
