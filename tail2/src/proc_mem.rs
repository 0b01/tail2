use std::{io::{BufReader, BufRead}, fs::File};
use thiserror::Error;
use std::io;

/// Parsed line for /proc/[pid]/maps
pub struct ProcMemMapEntry {
    /// avma address
    pub address_range: (u64, u64),
    /// is executable
    pub is_exec: bool,
    /// offset into the file
    pub offset: u64,
    /// path of the object file
    pub object_path: String,
}

/// Holds the memory map of a process, which can be obtained by reading `/proc/[pid]/map`.
///
/// This allows to translate virtual memory addresses inside a process into
/// a physical memory address, plus the path of the executable or library.
///
/// Example of a `/proc/[pid]/maps` entry:
/// 563b0178b000-563b01807000 r--p 00000000 00:40 3659174697971092           /home/myuser/code/ayatest/target/debug/ayatest
/// 563b01807000-563b01c4b000 r-xp 0007c000 00:40 3659174697971092           /home/myuser/code/ayatest/target/debug/ayatest
/// 563b01c4b000-563b01d85000 r--p 004c0000 00:40 3659174697971092           /home/myuser/code/ayatest/target/debug/ayatest
/// 563b01d86000-563b01dbe000 r--p 005fa000 00:40 3659174697971092           /home/myuser/code/ayatest/target/debug/ayatest
/// 563b01dbe000-563b01dbf000 rw-p 00632000 00:40 3659174697971092           /home/myuser/code/ayatest/target/debug/ayatest
/// 7f38911ff000-7f38913ff000 rw-p 00000000 00:00 0
/// 7f38913ff000-7f3891400000 ---p 00000000 00:00 0
/// 7f3891400000-7f3891402000 rw-p 00000000 00:00 0
/// 7f3891402000-7f3891403000 ---p 00000000 00:00 0
/// 7f3891403000-7f3891603000 rw-p 00000000 00:00 0
/// 7f3892fbc000-7f3892fbd000 r--p 00000000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
/// 7f3892fbd000-7f3892fe0000 r-xp 00001000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
/// 7f3892fe0000-7f3892fe8000 r--p 00024000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
/// 7f3892fe9000-7f3892fea000 r--p 0002c000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
/// 7f3892fea000-7f3892feb000 rw-p 0002d000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
pub struct ProcMemMap {
    pub entries: Vec<ProcMemMapEntry>,
}

/// Looks up information for a virtual address
#[derive(Debug)]
pub struct ProcMemMapLookupResult {
    /// Physical memory address
    pub address: u64,
    /// Executable or library path. This can be empty if there is no associated object on the filesystem
    pub object_path: String,
}

impl ProcMemMap {
    /// Loads the memory map for a given process from procfs
    pub fn from_process_id(pid: u32) -> Result<Self, ProcMemMapError> {
        let reader = BufReader::new(File::open(format!("/proc/{}/maps", pid)).map_err(|e| {
            ProcMemMapError::OpenError {
                process_id: pid,
                source: e,
            }
        })?);
        parse_maps(reader)
    }

    /// Tries to look up a virtual address, and obtain the physical address of a certain executable or library
    ///
    /// Returns `None` if the address can not be found
    pub fn lookup(&self, address: u64) -> Option<ProcMemMapLookupResult> {
        for entry in self.entries.iter() {
            if address >= entry.address_range.0 && address < entry.address_range.1 {
                let translated = address - entry.address_range.0 + entry.offset;

                return Some(ProcMemMapLookupResult {
                    address: translated,
                    object_path: entry.object_path.clone(),
                });
            }
        }

        None
    }
}

/// Error type for interaction with process memory maps
#[derive(Debug, Error)]
pub enum ProcMemMapError {
    /// Failed to read the context of the executable or library
    #[error("Failed to open memory map for process {process_id}")]
    OpenError {
        /// Process ID
        process_id: u32,
        /// The original io::Error
        source: io::Error,
    },
    /// Failed to read a full line in the process memory map
    #[error("Can not parse line")]
    ReadLineError {
        /// The original io::Error
        source: std::io::Error,
    },
    /// Failed to parse address information in the process memory map
    #[error("Can not parse address: Line: {line}")]
    InvalidAddress {
        /// The line which could not be parsed
        line: String,
    },
    /// Failed to parse permissions in the process memory map
    #[error("Can not parse permissions: Line: {line}")]
    InvalidPermissions {
        /// The line which could not be parsed
        line: String,
    },
    /// Failed to parse an offset in the process memory map
    #[error("Can not parse offset: Line: {line}")]
    InvalidOffset {
        /// The line which could not be parsed
        line: String,
    },
    /// Failed to parse device data in the process memory map
    #[error("Can not parse device: Line: {line}")]
    InvalidDevice {
        /// The line which could not be parsed
        line: String,
    },
    /// Failed to parse inode data in the process memory map
    #[error("Can not parse inode: Line: {line}")]
    InvalidInode {
        /// The line which could not be parsed
        line: String,
    },
}

fn parse_maps(reader: impl BufRead) -> Result<ProcMemMap, ProcMemMapError> {
    // See https://man7.org/linux/man-pages/man5/proc.5.html for details
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| ProcMemMapError::ReadLineError { source: e })?;
        let mut parts = line.splitn(6, ' ');
        let address = parts
            .next()
            .ok_or_else(|| ProcMemMapError::InvalidAddress { line: line.clone() })?;
        let mut address_parts = address.split('-');
        let start_address = address_parts
            .next()
            .and_then(|o| u64::from_str_radix(o, 16).ok())
            .ok_or_else(|| ProcMemMapError::InvalidAddress { line: line.clone() })?;
        let end_address = address_parts
            .next()
            .and_then(|o| u64::from_str_radix(o, 16).ok())
            .ok_or_else(|| ProcMemMapError::InvalidAddress { line: line.clone() })?;
        let perms = parts
            .next()
            .ok_or_else(|| ProcMemMapError::InvalidPermissions { line: line.clone() })?;
        let offset = parts
            .next()
            .and_then(|o| u64::from_str_radix(o, 16).ok())
            .ok_or_else(|| ProcMemMapError::InvalidOffset { line: line.clone() })?;
        let _dev = parts
            .next()
            .ok_or_else(|| ProcMemMapError::InvalidDevice { line: line.clone() })?;
        let _inode = parts
            .next()
            .ok_or_else(|| ProcMemMapError::InvalidInode { line: line.clone() })?;
        // TODO: Newlines in the path are escaped via an octal escape sequence.
        // We don't unescape it yet - therefore path with newlines are not supported
        let object_path = parts.next().unwrap_or("").trim().to_string();
        let is_exec = perms.contains('x');

        entries.push(ProcMemMapEntry {
            address_range: (start_address, end_address),
            is_exec,
            offset,
            object_path,
        });
    }

    Ok(ProcMemMap { entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_process_map() {
        let data = "563b0178b000-563b01807000 r--p 00000000 00:40 3659174697971092           /usr/bin/something/something\n\
            563b01807000-563b01c4b000 r-xp 0007c000 00:40 3659174697971092           /usr/bin/something/something\n\
            563b01c4b000-563b01d85000 r--p 004c0000 00:40 3659174697971092           /usr/bin/something/something\n\
            563b01d86000-563b01dbe000 r--p 005fa000 00:40 3659174697971092           /usr/bin/something/something\n\
            563b01dbe000-563b01dbf000 rw-p 00632000 00:40 3659174697971092           /usr/bin/something/something\n\
            7f38911ff000-7f38913ff000 rw-p 00000000 00:00 0\n\
            7f38913ff000-7f3891400000 ---p 00000000 00:00 0\n\
            7f3891400000-7f3891402000 rw-p 00000000 00:00 0\n\
            7f3891402000-7f3891403000 ---p 00000000 00:00 0\n\
            7f3891403000-7f3891603000 rw-p 00000000 00:00 0\n\
            7f3892fbc000-7f3892fbd000 r--p 00000000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so\n\
            7f3892fbd000-7f3892fe0000 r-xp 00001000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so\n\
            7f3892fe0000-7f3892fe8000 r--p 00024000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so\n\
            7f3892fe9000-7f3892fea000 r--p 0002c000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so\n\
            7f3892fea000-7f3892feb000 rw-p 0002d000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so\n\
            800000000000-900000000000 rw-p 00000000 00:00 0                          [stack:100000000000] ".as_bytes();
        let map = parse_maps(&mut BufReader::new(data)).unwrap();

        let result = map.lookup(0x563b01807200).unwrap();
        assert_eq!(result.address, 0x200 + 0x7c000);
        assert_eq!(
            result.object_path,
            "/usr/bin/something/something"
        );

        let result = map.lookup(0x7f3891400100).unwrap();
        assert_eq!(result.address, 0x100);
        assert_eq!(result.object_path, "");

        let result = map.lookup(0x7f3892fbe111).unwrap();
        assert_eq!(result.address, 0x1111 + 0x1000);
        assert_eq!(
            result.object_path,
            "/usr/lib/x86_64-linux-gnu/ld-2.31.so"
        );

        let result = map.lookup(0x800000005000).unwrap();
        assert_eq!(result.address, 0x5000);
        assert_eq!(result.object_path, "[stack:100000000000]");
    }
}