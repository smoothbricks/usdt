//! The empty implementation of the USDT crate.
//!
//! Used on platforms without DTrace.

// Copyright 2024 Oxide Computer Company
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

use crate::common;
use crate::{Probe, Provider};
use proc_macro2::TokenStream;
use quote::quote;

pub fn compile_provider_from_definition(
    provider: &Provider,
    config: &crate::CompileProvidersConfig,
) -> TokenStream {
    let probe_impls = provider
        .probes
        .iter()
        .map(|probe| compile_probe(provider, probe, config));
    let module = config.module_ident();
    quote! { pub(crate) mod #module { #(#probe_impls)* } }
}

fn compile_probe(
    provider: &Provider,
    probe: &Probe,
    config: &crate::CompileProvidersConfig,
) -> TokenStream {
    // We don't need to add any actual probe emission code, but we do still want
    // to perform type-checking of its arguments here.
    let args = common::call_argument_closure(&probe.types);
    let type_check_fn = common::construct_type_check(
        &provider.name,
        &probe.name,
        &provider.use_statements,
        &probe.types,
    );
    let impl_block = quote! {
        if false {
            #args
            #type_check_fn
        }
    };
    common::build_probe_macro(config, &probe.name, &probe.types, impl_block)
}

#[cfg(usdt_backend_noop)]
pub fn register_probes() -> Result<(), crate::Error> {
    Ok(())
}
