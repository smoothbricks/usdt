// Copyright 2022 Oxide Computer Company
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

use crate::target::StandardTarget;
use crate::DataType;

// Must be less than u8::MAX: record processing marks registered records with 255.
pub(crate) const PROBE_REC_VERSION: u8 = 1;

// Construct the ASM record for a probe. None denotes an is-enabled probe.
pub(crate) fn emit_probe_record(
    prov: &str,
    probe: &str,
    types: Option<&[DataType]>,
    target: StandardTarget,
) -> String {
    let section_ident = match target {
        StandardTarget::Freebsd => r#"set_dtrace_probes,"awR","progbits""#,
        StandardTarget::Illumos | StandardTarget::Solaris => r#"set_dtrace_probes,"aw","progbits""#,
    };
    let is_enabled = types.is_none();
    let n_args = types.map_or(0, |typ| typ.len());
    let arguments = types.map_or_else(String::new, |types| {
        types
            .iter()
            .map(|typ| format!(".asciz \"{}\"", typ.to_c_type()))
            .collect::<Vec<_>>()
            .join("\n")
    });
    format!(
        r#"
                    .pushsection {section_ident}
                    .balign 8
            991:
                    .4byte 992f-991b    // length
                    .byte {version}
                    .byte {n_args}
                    .2byte {flags}
                    .8byte 990b         // address
                    .asciz "{prov}"
                    .asciz "{probe}"
                    {arguments}         // null-terminated strings for each argument
                    .balign 8
            992:    .popsection
                    {yeet}
        "#,
        section_ident = section_ident,
        version = PROBE_REC_VERSION,
        n_args = n_args,
        flags = if is_enabled { 1 } else { 0 },
        prov = prov,
        probe = probe.replace("__", "-"),
        arguments = arguments,
        yeet = match target {
            // References from another section retain the probe section with
            // illumos and FreeBSD linkers.
            StandardTarget::Illumos | StandardTarget::Freebsd =>
                r#"
                    .pushsection yeet_dtrace_probes
                    .8byte 991b
                    .popsection
                "#,
            StandardTarget::Solaris => "",
        },
    )
}
