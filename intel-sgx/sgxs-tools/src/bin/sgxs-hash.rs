/* Copyright (c) Mithril Security.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fs::File;
use openssl::hash::Hasher;
use sgxs::sigstruct::EnclaveHash;

fn args_desc<'a>() -> clap::App<'a, 'a> {
    use clap::Arg;

    clap::App::new("sgxs-hash")
        .about("Compute MRENCLAVE of a SGXS input file")
        .arg(
            Arg::with_name("input")
                .required(true)
                .help("The enclave SGXS file that will be hashed"),
        )
}

fn main() {
    let matches = args_desc().get_matches();
    let mut sgxsfile =
        File::open(matches.value_of("input").unwrap()).expect("Unable to open input SGXS file");
    let enclave_hash = EnclaveHash::from_stream::<_, Hasher>(&mut sgxsfile)
        .expect("Unable to read input SGXS file");

    println!("{}", base16::encode_lower(&enclave_hash.hash));
}