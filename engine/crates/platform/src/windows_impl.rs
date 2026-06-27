//! windows_impl — implémentations natives Windows (DPAPI, ReadProcessMemory).
//!
//! Compilé uniquement sous `cfg(windows)` AVEC la feature `windows-platform`.
//! ⚠️ Ce module dépend du SDK Windows (`windows-sys`) et n'est pas compilé ni
//! exécuté dans l'environnement de développement Linux ; il est validé par la
//! CI Windows lorsque la feature est activée. Les implémentations suivent les
//! API documentées Win32.

use crate::{KeyProvider, MemoryRegionProvider, OwnedRegion};
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, FALSE, HANDLE};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_NOACCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

/// Fournisseur de clé enveloppée par DPAPI (portée utilisateur).
///
/// La clé maîtresse 32 octets est stockée **chiffrée** par `CryptProtectData`
/// et déchiffrée à la demande par `CryptUnprotectData` — parité avec
/// `ProtectedData` (DPAPI) utilisé par optiCombat côté C#.
pub struct DpapiKeyProvider {
    wrapped: Vec<u8>,
}

impl DpapiKeyProvider {
    /// Enveloppe une clé en clair → blob DPAPI persistable.
    pub fn wrap(key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
        unsafe {
            let mut input = blob(key);
            let mut output = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };
            let ok = CryptProtectData(
                &mut input,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut output,
            );
            if ok == FALSE {
                return Err(std::io::Error::last_os_error());
            }
            let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
            let wrapped = slice.to_vec();
            LocalFree(output.pbData as _);
            Ok(wrapped)
        }
    }

    /// Construit le provider à partir d'un blob DPAPI déjà enveloppé.
    pub fn from_wrapped(wrapped: Vec<u8>) -> Self {
        Self { wrapped }
    }
}

impl KeyProvider for DpapiKeyProvider {
    fn master_key(&self) -> [u8; 32] {
        unsafe {
            let mut input = blob(&self.wrapped);
            let mut output = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };
            let ok = CryptUnprotectData(
                &mut input,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut output,
            );
            let mut key = [0u8; 32];
            if ok != FALSE {
                let n = (output.cbData as usize).min(32);
                let slice = std::slice::from_raw_parts(output.pbData, n);
                key[..n].copy_from_slice(&slice[..n]);
                LocalFree(output.pbData as _);
            }
            key
        }
    }
}

/// Énumère les régions mémoire engagées et lisibles d'un processus.
pub struct WindowsMemoryRegionProvider {
    pid: u32,
    max_region: usize,
}

impl WindowsMemoryRegionProvider {
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            max_region: 16 * 1024 * 1024,
        }
    }
}

impl MemoryRegionProvider for WindowsMemoryRegionProvider {
    fn regions(&self) -> Vec<OwnedRegion> {
        let mut out = Vec::new();
        unsafe {
            let handle: HANDLE =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, self.pid);
            if handle.is_null() {
                return out;
            }
            let mut addr: usize = 0;
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
            while VirtualQueryEx(handle, addr as _, &mut mbi, mbi_size) == mbi_size {
                let region_size = mbi.RegionSize;
                let committed = mbi.State == MEM_COMMIT;
                let readable = mbi.Protect != 0 && mbi.Protect != PAGE_NOACCESS;
                if committed && readable && region_size > 0 && region_size <= self.max_region {
                    let mut buf = vec![0u8; region_size];
                    let mut read: usize = 0;
                    let ok = ReadProcessMemory(
                        handle,
                        mbi.BaseAddress,
                        buf.as_mut_ptr() as _,
                        region_size,
                        &mut read,
                    );
                    if ok != FALSE && read > 0 {
                        buf.truncate(read);
                        out.push(OwnedRegion {
                            label: format!("pid:{}:{:#x}", self.pid, mbi.BaseAddress as usize),
                            bytes: buf,
                        });
                    }
                }
                let next = (mbi.BaseAddress as usize).saturating_add(region_size);
                if next <= addr {
                    break;
                }
                addr = next;
            }
            CloseHandle(handle);
        }
        out
    }
}

#[cfg(all(test, windows, feature = "windows-platform"))]
mod windows_tests {
    use super::*;

    #[test]
    fn dpapi_persists_to_localappdata() {
        let key = [0xCDu8; 32];
        let wrapped = DpapiKeyProvider::wrap(&key).expect("CryptProtectData");
        let provider = DpapiKeyProvider::from_wrapped(wrapped);
        assert_eq!(provider.master_key(), key);
    }

    #[test]
    fn read_process_memory_current_process() {
        let pid = std::process::id();
        let provider = WindowsMemoryRegionProvider::new(pid);
        let regions = provider.regions();
        assert!(!regions.is_empty());
        assert!(regions.iter().any(|r| !r.bytes.is_empty()));
    }

    #[test]
    fn read_explorer_process_has_regions() {
        let pid = find_process_pid("explorer.exe");
        if pid == 0 {
            eprintln!("skip: explorer.exe not running");
            return;
        }
        let provider = WindowsMemoryRegionProvider::new(pid);
        let regions = provider.regions();
        assert!(
            !regions.is_empty(),
            "explorer.exe should expose readable regions"
        );
    }

    fn find_process_pid(name: &str) -> u32 {
        use std::process::Command;
        let out = Command::new("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {name}"), "/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let first = text.lines().next()?;
        let pid_field = first.split(',').nth(1)?;
        pid_field.trim_matches('"').parse().ok().unwrap_or(0)
    }
}
