/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::Error as IoError;
use std::ptr;
use std::sync::Arc;

use nix::sys::mman::{mmap, mprotect, munmap, ProtFlags};
use sgx_isa::{Attributes, Einittoken, Miscselect, PageType, SecinfoFlags, Sigstruct};
use sgxs::loader;
use sgxs::sgxs::{MeasEAdd, MeasECreate, PageChunks, SgxsRead};

use crate::generic::{self, EinittokenError, EnclaveLoad, Mapping};
use crate::{MappingInfo, Tcs};

use super::{Enclave, SIMULATED_ENCLAVES};

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Failed to map enclave into memory.")]
    Map(#[cause] IoError),
    #[fail(display = "Failed to load enclave page.")]
    Add(#[cause] IoError),
}

impl EinittokenError for Error {
    fn is_einittoken_error(&self) -> bool {
        false
    }
}

impl EnclaveLoad for InnerDevice {
    type Error = Error;
    type MapData = ();

    fn new(
        device: Arc<InnerDevice>,
        ecreate: MeasECreate,
        _attributes: Attributes,
        _miscselect: Miscselect,
    ) -> Result<Mapping<Self>, Self::Error> {
        let ptr = unsafe {
            mmap(
                ptr::null_mut(),
                ecreate.size as usize,
                nix::sys::mman::ProtFlags::PROT_NONE,
                nix::sys::mman::MapFlags::MAP_PRIVATE | nix::sys::mman::MapFlags::MAP_ANONYMOUS,
                -1,
                0,
            )
        }
        .map_err(|_| Error::Map(IoError::last_os_error()))?;

        let mapping = Mapping {
            device,
            base: ptr as u64,
            size: ecreate.size,
            tcss: vec![],
            mapdata: (),
        };

        // TODO: measure

        Ok(mapping)
    }

    fn add(
        mapping: &mut Mapping<Self>,
        page: (MeasEAdd, PageChunks, [u8; 4096]),
    ) -> Result<(), Self::Error> {
        let (eadd, _chunks, data) = page;

        let mut prot = ProtFlags::PROT_NONE;
        if eadd.secinfo.flags.intersects(SecinfoFlags::R) {
            prot |= nix::sys::mman::ProtFlags::PROT_READ;
        }
        if eadd.secinfo.flags.intersects(SecinfoFlags::W) {
            prot |= nix::sys::mman::ProtFlags::PROT_WRITE;
        }
        if eadd.secinfo.flags.intersects(SecinfoFlags::X) {
            prot |= nix::sys::mman::ProtFlags::PROT_EXEC;
        }
        if eadd.secinfo.flags.page_type() == PageType::Tcs as u8 {
            prot |= nix::sys::mman::ProtFlags::PROT_READ;
        }

        unsafe {
            let page_addr = mapping.base + eadd.offset;
            mprotect(
                page_addr as _,
                data.len(),
                nix::sys::mman::ProtFlags::PROT_WRITE,
            )
            .map_err(|_| Error::Add(IoError::last_os_error()))?;
            ptr::copy_nonoverlapping(data.as_ptr(), page_addr as _, data.len());
            mprotect(page_addr as _, data.len(), prot)
                .map_err(|_| Error::Add(IoError::last_os_error()))?;
        }

        // TODO: measure

        Ok(())
    }

    fn init(
        mapping: &mut Mapping<Self>,
        _sigstruct: &Sigstruct,
        _einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error> {
        // TODO: measure

        *SIMULATED_ENCLAVES.lock() = Some((
            mapping.base,
            Enclave {
                base: mapping.base,
                size: mapping.size,
                tcss: mapping
                    .tcss
                    .iter()
                    .map(|&a| (a, Default::default()))
                    .collect(),
            },
        ));

        Ok(())
    }

    fn destroy(mapping: &mut Mapping<Self>) {
        *SIMULATED_ENCLAVES.lock() = None;
        unsafe { munmap(mapping.base as usize as *mut _, mapping.size as usize) }.unwrap();
    }
}

#[derive(Debug)]
struct InnerDevice {}

#[derive(Debug)]
// there is no builder since EINITTOKENs are not supported
pub struct Simulator {
    inner: generic::Device<InnerDevice>,
}

impl Simulator {
    pub fn new() -> Simulator {
        Simulator {
            inner: generic::DeviceBuilder {
                device: generic::Device {
                    inner: Arc::new(InnerDevice {}),
                    einittoken_provider: None,
                },
            }
            .build(),
        }
    }
}

impl loader::Load for Simulator {
    type MappingInfo = MappingInfo;
    type Tcs = Tcs;

    fn load<R: SgxsRead>(
        &mut self,
        reader: &mut R,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> ::std::result::Result<loader::Mapping<Self>, ::failure::Error> {
        self.inner
            .load(reader, sigstruct, attributes, miscselect)
            .map(Into::into)
    }
}
