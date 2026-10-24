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

use proc_macro2::TokenStream;
use quote::quote;
use serde::Deserialize;

/// The target selected by cfg attributes in the consuming crate, not this crate.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    MacosX86_64,
    MacosAarch64,
    LinuxX86_64,
    LinuxAarch64,
    IllumosX86_64,
    SolarisX86_64,
    FreebsdX86_64,
    Noop,
}

#[derive(Clone, Copy)]
pub(crate) enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Clone, Copy)]
pub(crate) enum StandardTarget {
    Illumos,
    Solaris,
    Freebsd,
}

/// Configuration for the second, consumer-selected macro expansion.
#[derive(Deserialize)]
pub struct TargetConfig {
    pub target: Target,
    pub config: crate::CompileProvidersConfig,
}

/// Emit only small, cfg-gated invocations. The unselected macros never expand,
/// so their code generators and platform tools are not run on the host.
pub fn dispatch(mut expand: impl FnMut(&syn::Ident) -> TokenStream) -> TokenStream {
    let targets = [
        (
            "macos_x86_64",
            quote! { all(target_os = "macos", target_arch = "x86_64", target_pointer_width = "64") },
        ),
        (
            "macos_aarch64",
            quote! { all(target_os = "macos", target_arch = "aarch64", target_pointer_width = "64") },
        ),
        (
            "linux_x86_64",
            quote! { all(target_os = "linux", target_arch = "x86_64", target_pointer_width = "64") },
        ),
        (
            "linux_aarch64",
            quote! { all(target_os = "linux", target_arch = "aarch64", target_pointer_width = "64") },
        ),
        (
            "illumos_x86_64",
            quote! { all(target_os = "illumos", target_arch = "x86_64", target_pointer_width = "64") },
        ),
        (
            "solaris_x86_64",
            quote! { all(target_os = "solaris", target_arch = "x86_64", target_pointer_width = "64") },
        ),
        (
            "freebsd_x86_64",
            quote! { all(target_os = "freebsd", target_arch = "x86_64", target_pointer_width = "64") },
        ),
        (
            "noop",
            quote! { not(any(target_os = "macos", target_os = "linux", target_os = "illumos", target_os = "solaris", target_os = "freebsd")) },
        ),
    ];
    let invocations = targets.iter().map(|(target, cfg)| {
        let invocation = expand(&quote::format_ident!("{}", target));
        quote! { #[cfg(#cfg)] #invocation }
    });
    let supported = targets.iter().map(|(_, cfg)| cfg);
    quote! {
        #(#invocations)*
        #[cfg(not(any(#(#supported),*)))]
        compile_error!("USDT does not support this target architecture or pointer width");
    }
}
