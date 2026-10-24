//! Uninstrumented consumer used as the negative control for the
//! cross-target proof: it defines no probes at all, so its compiled objects
//! must carry no probe metadata. If probe generation ever degraded to a
//! no-op for a cross-compiled target, the instrumented consumers would look
//! exactly like this crate, and the proof's metadata checks would fail.

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

/// Plain computation with the same argument widths as the instrumented
/// consumers' work probe, but without any probes.
#[inline(never)]
pub fn work(a: u8, b: u64, c: u32, d: i32) -> u64 {
    std::hint::black_box(
        b.wrapping_add(u64::from(a))
            .wrapping_add(u64::from(c))
            .wrapping_add(d as i64 as u64),
    )
}

/// Plain no-work function, mirroring the instrumented consumers' done probe.
#[inline(never)]
pub fn done() {
    std::hint::black_box(());
}

/// Run the plain equivalents of the instrumented consumers' probe sites.
#[inline(never)]
pub fn run() -> u64 {
    let out = work(7, 8, 9, -10);
    done();
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn plain_work_computes() {
        assert_eq!(super::run(), 14);
    }
}
