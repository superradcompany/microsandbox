// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(unix)]
pub use vmm_sys_util::{errno, tempdir, tempfile, terminal};
#[cfg(windows)]
pub mod errno {
    pub type Error = std::io::Error;
    pub type Result<T> = std::io::Result<T>;
}
#[cfg(target_os = "linux")]
pub use vmm_sys_util::{eventfd, ioctl};

pub mod byte_order;
pub mod event;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::epoll;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::epoll;
#[cfg(target_os = "macos")]
pub use macos::eventfd;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::epoll;
#[cfg(target_os = "windows")]
pub use windows::eventfd;
pub mod metrics;
pub mod pollable_channel;
#[cfg(target_arch = "x86_64")]
pub mod rand;
#[cfg(target_os = "linux")]
pub mod signal;
pub mod sized_vec;
pub mod sm;
pub mod syscall;
pub mod time;
pub mod timerfd;
pub mod worker_message;

pub fn page_size() -> usize {
    #[cfg(unix)]
    {
        unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() }
    }

    #[cfg(windows)]
    {
        let mut info = windows_sys::Win32::System::SystemInformation::SYSTEM_INFO::default();
        unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemInfo(&mut info);
        }
        info.dwPageSize as usize
    }
}

#[macro_export]
macro_rules! align_upwards {
    ($addr:expr, $alignment:expr) => {{
        let alignment = $alignment;
        ($addr + alignment - 1) & !(alignment - 1)
    }};
}
