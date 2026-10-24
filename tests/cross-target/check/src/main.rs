//! Inspect compiled consumer objects for USDT probe metadata.
//!
//! The input may be a single object file or executable, or an archive such
//! as the rlib produced by building a consumer library. Archives are
//! inspected member by member, so a consumer library can be checked without
//! linking it -- which means a cross-compiled library can be checked on the
//! build host without a cross linker, a tracer, or elevated privileges.
//!
//! Two kinds of metadata are recognized, matching the two backends this
//! proof exercises:
//!
//! - ELF (Linux) objects carry one .note.stapsdt note per probe site. Each
//!   note records the provider name, the probe name, and the argument ABI
//!   string (one size/register operand per argument, in order).
//! - Mach-O (macOS) objects carry references to the linker-synthesized
//!   dtrace probe and is-enabled symbols for each probe.
//!
//! Usage:
//!
//!   cross-target-check --stapsdt FILE PROVIDER:PROBE=ARGUMENTS...
//!   cross-target-check --mach-o FILE PROVIDER:PROBE...
//!   cross-target-check --none FILE
//!
//! In --stapsdt mode the set of note records (with multiplicity) must match
//! the expectations exactly, and every ELF object must be an x86-64 object.
//! In --mach-o mode each expected probe must have both its probe and its
//! is-enabled symbol, and no other probe symbols may be present. In --none
//! mode no probe metadata of either kind may be present; that mode exists
//! for the uninstrumented negative-control consumer.

// Copyright 2026 Oxide Computer Company
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

use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;

const USAGE: &str = "usage:\n  cross-target-check --stapsdt <file> <provider>:<probe>=<arguments>...\n  cross-target-check --mach-o <file> <provider>:<probe>...\n  cross-target-check --none <file>";

/// ELF note type for SystemTap probe descriptors.
const NT_STAPSDT: u32 = 3;

/// One probe record decoded from a .note.stapsdt ELF note.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StapsdtRecord {
    provider: String,
    probe: String,
    arguments: String,
}

/// Which of the two linker-synthesized Mach-O symbols a name refers to.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DtraceSymbolKind {
    Probe,
    IsEnabled,
}

impl DtraceSymbolKind {
    fn name(self) -> &'static str {
        match self {
            DtraceSymbolKind::Probe => "dtrace_probe",
            DtraceSymbolKind::IsEnabled => "dtrace_isenabled",
        }
    }
}

/// Everything found in one input file.
#[derive(Default)]
struct Findings {
    stapsdt: Vec<StapsdtRecord>,
    dtrace_symbols: BTreeSet<(DtraceSymbolKind, String, String)>,
    elf_objects: usize,
    elf_machines: BTreeSet<u16>,
    mach_o_objects: usize,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("cross-target-check: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().ok_or_else(|| USAGE.to_string())?;
    let path = args.next().ok_or_else(|| USAGE.to_string())?;
    let expectations: Vec<String> = args.collect();

    let bytes = std::fs::read(&path).map_err(|err| format!("failed to read {path}: {err}"))?;
    let findings = inspect(&bytes).map_err(|err| format!("{path}: {err}"))?;
    print_findings(&findings);

    match mode.as_str() {
        "--stapsdt" => check_stapsdt(&findings, &expectations),
        "--mach-o" => check_mach_o(&findings, &expectations),
        "--none" => check_none(&findings, &expectations),
        other => Err(format!("unknown mode: {other}\n{USAGE}")),
    }?;
    println!("ok: {path} satisfies the {mode} expectations");
    Ok(())
}

fn print_findings(findings: &Findings) {
    let machines: Vec<String> = findings
        .elf_machines
        .iter()
        .map(|machine| machine.to_string())
        .collect();
    let machines = if machines.is_empty() {
        "-".to_string()
    } else {
        machines.join(",")
    };
    println!(
        "objects: {} ELF (machine: {}), {} Mach-O",
        findings.elf_objects, machines, findings.mach_o_objects,
    );
    let mut records = findings.stapsdt.clone();
    records.sort();
    for record in &records {
        println!(
            "stapsdt provider={} probe={} arguments={:?}",
            record.provider, record.probe, record.arguments,
        );
    }
    for (kind, provider, probe) in &findings.dtrace_symbols {
        println!(
            "mach-o {} provider={} probe={}",
            kind.name(),
            provider,
            probe
        );
    }
}

/// Inspect every object in the input: each member if the input is an
/// archive, otherwise the input itself.
fn inspect(bytes: &[u8]) -> Result<Findings, String> {
    let mut findings = Findings::default();
    for (name, member) in object_members(bytes)? {
        if member.starts_with(b"\x7fELF") {
            findings.elf_objects += 1;
            inspect_elf(member, &mut findings).map_err(|err| format!("{name}: {err}"))?;
        } else if is_thin_mach_o(member) {
            findings.mach_o_objects += 1;
            inspect_mach_o(member, &mut findings).map_err(|err| format!("{name}: {err}"))?;
        } else if is_fat_mach_o(member) {
            return Err(format!(
                "{name}: fat (universal) Mach-O inputs are not supported; \
                 pass a thin object, executable, or rlib"
            ));
        }
        // Any other archive member (metadata, Rust metadata, and similar)
        // carries no probe metadata and is ignored.
    }
    if findings.elf_objects + findings.mach_o_objects == 0 {
        return Err("no ELF or Mach-O object found".to_string());
    }
    Ok(findings)
}

/// Split an archive into its members, or treat the input as one object.
fn object_members(bytes: &[u8]) -> Result<Vec<(String, &[u8])>, String> {
    if !bytes.starts_with(b"!<arch>\n") {
        return Ok(vec![("<file>".to_string(), bytes)]);
    }
    let archive = goblin::archive::Archive::parse(bytes).map_err(|err| err.to_string())?;
    let mut members = Vec::new();
    // summarize walks every archive member, including any that share a name.
    for (name, member, _symbols) in archive.summarize() {
        let start = usize::try_from(member.offset)
            .map_err(|_| format!("archive member {name} has an out-of-range offset"))?;
        let end = start
            .checked_add(member.size())
            .ok_or_else(|| format!("archive member {name} size overflows"))?;
        let slice = bytes
            .get(start..end)
            .ok_or_else(|| format!("archive member {name} extends past end of file"))?;
        members.push((name.to_string(), slice));
    }
    Ok(members)
}

fn inspect_elf(bytes: &[u8], findings: &mut Findings) -> Result<(), String> {
    let elf = goblin::elf::Elf::parse(bytes).map_err(|err| err.to_string())?;
    findings.elf_machines.insert(elf.header.e_machine);
    for section in elf.section_headers.iter() {
        let Some(name) = elf.shdr_strtab.get_at(section.sh_name) else {
            continue;
        };
        if name != ".note.stapsdt" {
            continue;
        }
        let start = usize::try_from(section.sh_offset)
            .map_err(|_| ".note.stapsdt section has an out-of-range offset".to_string())?;
        let size = usize::try_from(section.sh_size)
            .map_err(|_| ".note.stapsdt section has an out-of-range size".to_string())?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| ".note.stapsdt section size overflows".to_string())?;
        let data = bytes
            .get(start..end)
            .ok_or_else(|| ".note.stapsdt section extends past end of file".to_string())?;
        findings.stapsdt.extend(parse_stapsdt_notes(data)?);
    }
    Ok(())
}

fn inspect_mach_o(bytes: &[u8], findings: &mut Findings) -> Result<(), String> {
    let mach = goblin::mach::MachO::parse(bytes, 0).map_err(|err| err.to_string())?;
    for symbol in mach.symbols() {
        let (name, _nlist) = symbol.map_err(|err| err.to_string())?;
        if let Some(parsed) = parse_dtrace_symbol(name) {
            findings.dtrace_symbols.insert(parsed);
        }
    }
    Ok(())
}

fn leading_u32_le(bytes: &[u8]) -> Option<u32> {
    let first: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(first))
}

fn is_thin_mach_o(bytes: &[u8]) -> bool {
    // 32- and 64-bit Mach-O magics, in either byte order.
    matches!(
        leading_u32_le(bytes),
        Some(0xfeed_face | 0xfeed_facf | 0xcefa_edfe | 0xcffa_edfe)
    )
}

fn is_fat_mach_o(bytes: &[u8]) -> bool {
    matches!(leading_u32_le(bytes), Some(0xbeba_feca | 0xcafe_babe))
}

/// Parse every ELF note in a .note.stapsdt section. Notes are little-endian
/// in the x86-64 objects this checker accepts for --stapsdt.
fn parse_stapsdt_notes(data: &[u8]) -> Result<Vec<StapsdtRecord>, String> {
    let mut records = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        // A section may be padded with trailing zero bytes.
        if rest.iter().all(|&byte| byte == 0) {
            break;
        }
        if rest.len() < 12 {
            return Err(format!(
                "truncated ELF note header: {} byte(s) remain",
                rest.len()
            ));
        }
        let namesz = u32_le(&rest[0..4]) as usize;
        let descsz = u32_le(&rest[4..8]) as usize;
        let note_type = u32_le(&rest[8..12]);
        let name = rest
            .get(
                12..12usize
                    .checked_add(namesz)
                    .ok_or("ELF note name size overflow")?,
            )
            .ok_or("ELF note name extends past end of section")?;
        let desc_start = 12usize
            .checked_add(align4(namesz)?)
            .ok_or("ELF note descriptor offset overflow")?;
        let desc_end = desc_start
            .checked_add(descsz)
            .ok_or("ELF note descriptor size overflow")?;
        let desc = rest
            .get(desc_start..desc_end)
            .ok_or("ELF note descriptor extends past end of section")?;

        if note_type != NT_STAPSDT {
            return Err(format!(
                "note in .note.stapsdt has type {note_type}, expected NT_STAPSDT ({NT_STAPSDT})"
            ));
        }
        if name != b"stapsdt\0" {
            return Err(format!(
                "note in .note.stapsdt has unexpected name {name:?}, expected stapsdt"
            ));
        }
        records.push(parse_stapsdt_desc(desc)?);

        if desc_end == rest.len() {
            rest = &rest[rest.len()..];
        } else {
            let next = desc_start
                .checked_add(align4(descsz)?)
                .ok_or("ELF note size overflow")?;
            rest = rest
                .get(next..)
                .ok_or("ELF note padding extends past end of section")?;
        }
    }
    Ok(records)
}

/// Parse one stapsdt note descriptor: three 64-bit addresses (probe
/// location, base, and semaphore) followed by the provider name, probe
/// name, and argument ABI string, each NUL-terminated. In a relocatable
/// object the addresses are zero until link-time relocation, so only the
/// strings identify the probe here.
fn parse_stapsdt_desc(desc: &[u8]) -> Result<StapsdtRecord, String> {
    let mut rest = desc
        .get(24..)
        .ok_or("stapsdt descriptor is shorter than its three address fields")?;
    let provider = read_c_string(&mut rest, "provider")?;
    let probe = read_c_string(&mut rest, "probe")?;
    let arguments = read_c_string(&mut rest, "arguments")?;
    if provider.is_empty() || probe.is_empty() {
        return Err("stapsdt descriptor has an empty provider or probe name".to_string());
    }
    if !rest.is_empty() {
        return Err(format!(
            "stapsdt descriptor for {provider}:{probe} has {} trailing byte(s)",
            rest.len()
        ));
    }
    Ok(StapsdtRecord {
        provider,
        probe,
        arguments,
    })
}

fn read_c_string(data: &mut &[u8], what: &str) -> Result<String, String> {
    let end = data
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| format!("stapsdt descriptor {what} string is not NUL-terminated"))?;
    let text = std::str::from_utf8(&data[..end])
        .map_err(|err| format!("stapsdt descriptor {what} string is not UTF-8: {err}"))?;
    let text = text.to_string();
    *data = &data[end + 1..];
    Ok(text)
}

fn u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn align4(value: usize) -> Result<usize, String> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| "ELF note size overflow".to_string())
}

/// Parse a Mach-O symbol name of the form that the macOS linker synthesizes
/// for DTrace probes. Mach-O symbol names carry leading underscores, and the
/// final component is an opaque version/hash suffix assigned when the
/// provider header was generated, so it is required to be present but its
/// value is not interpreted.
fn parse_dtrace_symbol(name: &str) -> Option<(DtraceSymbolKind, String, String)> {
    let trimmed = name.trim_start_matches('_');
    let (kind, rest) = if let Some(rest) = trimmed.strip_prefix("dtrace_probe$") {
        (DtraceSymbolKind::Probe, rest)
    } else if let Some(rest) = trimmed.strip_prefix("dtrace_isenabled$") {
        (DtraceSymbolKind::IsEnabled, rest)
    } else {
        return None;
    };
    let mut parts = rest.split('$');
    let provider = parts.next()?;
    let probe = parts.next()?;
    parts.next()?;
    if provider.is_empty() || probe.is_empty() {
        return None;
    }
    Some((kind, provider.to_string(), probe.to_string()))
}

fn parse_identity(text: &str) -> Result<(String, String), String> {
    let Some((provider, probe)) = text.split_once(':') else {
        return Err(format!(
            "invalid expectation {text:?}: expected <provider>:<probe>"
        ));
    };
    if provider.is_empty() || probe.is_empty() || probe.contains(':') {
        return Err(format!(
            "invalid expectation {text:?}: expected <provider>:<probe>"
        ));
    }
    Ok((provider.to_string(), probe.to_string()))
}

fn parse_stapsdt_expectation(text: &str) -> Result<StapsdtRecord, String> {
    let Some((identity, arguments)) = text.split_once('=') else {
        return Err(format!(
            "invalid stapsdt expectation {text:?}: expected <provider>:<probe>=<arguments>"
        ));
    };
    let (provider, probe) = parse_identity(identity)?;
    Ok(StapsdtRecord {
        provider,
        probe,
        arguments: arguments.to_string(),
    })
}

fn format_record(record: &StapsdtRecord) -> String {
    format!(
        "{}:{}={:?}",
        record.provider, record.probe, record.arguments
    )
}

fn tally(records: &[StapsdtRecord]) -> BTreeMap<StapsdtRecord, usize> {
    let mut counts = BTreeMap::new();
    for record in records {
        *counts.entry(record.clone()).or_insert(0) += 1;
    }
    counts
}

fn check_stapsdt(findings: &Findings, expectations: &[String]) -> Result<(), String> {
    if expectations.is_empty() {
        return Err("--stapsdt requires at least one expectation".to_string());
    }
    if findings.elf_objects == 0 {
        return Err(
            "no ELF object found; a wrong-backend or no-op build cannot satisfy --stapsdt"
                .to_string(),
        );
    }
    let x86_64 = goblin::elf::header::EM_X86_64;
    if findings
        .elf_machines
        .iter()
        .any(|&machine| machine != x86_64)
    {
        return Err(format!(
            "ELF machine(s) {:?} are not all x86-64 ({x86_64})",
            findings.elf_machines,
        ));
    }
    let expected = expectations
        .iter()
        .map(|text| parse_stapsdt_expectation(text))
        .collect::<Result<Vec<_>, _>>()?;
    let expected = tally(&expected);
    let actual = tally(&findings.stapsdt);

    let mut problems = Vec::new();
    for (record, want) in &expected {
        let got = actual.get(record).copied().unwrap_or(0);
        if got != *want {
            problems.push(format!(
                "record count mismatch for {} (want {want}, found {got})",
                format_record(record),
            ));
        }
    }
    for (record, got) in &actual {
        if !expected.contains_key(record) {
            problems.push(format!(
                "unexpected record {} (found {got})",
                format_record(record),
            ));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

fn check_mach_o(findings: &Findings, expectations: &[String]) -> Result<(), String> {
    if expectations.is_empty() {
        return Err("--mach-o requires at least one expectation".to_string());
    }
    if findings.mach_o_objects == 0 {
        return Err(
            "no Mach-O object found; a wrong-backend or no-op build cannot satisfy --mach-o"
                .to_string(),
        );
    }
    let expected: BTreeSet<(String, String)> = expectations
        .iter()
        .map(|text| parse_identity(text))
        .collect::<Result<_, _>>()?;

    let mut problems = Vec::new();
    for (provider, probe) in &expected {
        for kind in [DtraceSymbolKind::Probe, DtraceSymbolKind::IsEnabled] {
            if !findings
                .dtrace_symbols
                .contains(&(kind, provider.clone(), probe.clone()))
            {
                problems.push(format!(
                    "missing {} symbol for {provider}:{probe}",
                    kind.name(),
                ));
            }
        }
    }
    let found: BTreeSet<(String, String)> = findings
        .dtrace_symbols
        .iter()
        .map(|(_kind, provider, probe)| (provider.clone(), probe.clone()))
        .collect();
    for (provider, probe) in found.difference(&expected) {
        problems.push(format!("unexpected probe symbol(s) for {provider}:{probe}"));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

fn check_none(findings: &Findings, expectations: &[String]) -> Result<(), String> {
    if !expectations.is_empty() {
        return Err("--none takes no expectations".to_string());
    }
    let mut problems = Vec::new();
    if !findings.stapsdt.is_empty() {
        problems.push(format!(
            "found {} stapsdt note record(s) in an object expected to have none",
            findings.stapsdt.len(),
        ));
    }
    if !findings.dtrace_symbols.is_empty() {
        problems.push(format!(
            "found {} Mach-O dtrace symbol(s) in an object expected to have none",
            findings.dtrace_symbols.len(),
        ));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(provider: &str, probe: &str, arguments: &str) -> Vec<u8> {
        let mut desc = vec![0u8; 24];
        for text in [provider, probe, arguments] {
            desc.extend_from_slice(text.as_bytes());
            desc.push(0);
        }
        let name = b"stapsdt\0";
        let mut out = Vec::new();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        out.extend_from_slice(&NT_STAPSDT.to_le_bytes());
        out.extend_from_slice(name);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&desc);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    #[test]
    fn parses_notes_with_and_without_arguments() {
        let mut section = note("crossattr", "work", "1@%dil 8@%rsi");
        section.extend_from_slice(&note("crossattr", "done", ""));
        let records = parse_stapsdt_notes(&section).expect("notes parse");
        assert_eq!(
            records,
            vec![
                StapsdtRecord {
                    provider: "crossattr".to_string(),
                    probe: "work".to_string(),
                    arguments: "1@%dil 8@%rsi".to_string(),
                },
                StapsdtRecord {
                    provider: "crossattr".to_string(),
                    probe: "done".to_string(),
                    arguments: String::new(),
                },
            ],
        );
    }

    #[test]
    fn rejects_wrong_note_type_and_truncated_notes() {
        let mut section = note("crossattr", "work", "");
        section[8] = 7;
        assert!(parse_stapsdt_notes(&section).is_err());

        let section = note("crossattr", "work", "");
        assert!(parse_stapsdt_notes(&section[..section.len() - 2]).is_err());
        assert!(parse_stapsdt_notes(&[1, 2, 3]).is_err());
    }

    #[test]
    fn rejects_descriptor_with_trailing_bytes() {
        let mut desc = vec![0u8; 24];
        desc.extend_from_slice(b"prov\0work\0\0trailing");
        assert!(parse_stapsdt_desc(&desc).is_err());
        assert!(parse_stapsdt_desc(&[0u8; 8]).is_err());
    }

    #[test]
    fn parses_dtrace_symbols() {
        assert_eq!(
            parse_dtrace_symbol("___dtrace_probe$crossattr$work$v1"),
            Some((
                DtraceSymbolKind::Probe,
                "crossattr".to_string(),
                "work".to_string(),
            )),
        );
        assert_eq!(
            parse_dtrace_symbol("__dtrace_isenabled$crossattr$done$abc"),
            Some((
                DtraceSymbolKind::IsEnabled,
                "crossattr".to_string(),
                "done".to_string(),
            )),
        );
        assert_eq!(
            parse_dtrace_symbol("___dtrace_stability$crossattr$v1$1_1"),
            None
        );
        assert_eq!(parse_dtrace_symbol("__dtrace_probe$crossattr$work"), None);
        assert_eq!(parse_dtrace_symbol("_crossattr_work"), None);
    }

    #[test]
    fn parses_expectations() {
        let record =
            parse_stapsdt_expectation("crossattr:work=1@%dil 8@%rsi").expect("expectation parses");
        assert_eq!(record.provider, "crossattr");
        assert_eq!(record.probe, "work");
        assert_eq!(record.arguments, "1@%dil 8@%rsi");
        assert!(parse_stapsdt_expectation("crossattr:work").is_err());
        assert!(parse_stapsdt_expectation("crossattrwork=1@%dil").is_err());
        assert!(parse_identity("crossattr:").is_err());
    }
}
