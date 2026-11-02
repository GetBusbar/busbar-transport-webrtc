// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ValidateIn};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    in_head, out_head, Bind, Called, ConnTable, Dispatcher, Frame, InFrame, NoSink, OutFrame,
    Plugin,
};
use std::sync::Arc;

pub fn input<T: InFrame>() -> T {
    // SAFETY: ABI inputs consist of plain C fields with a valid zero representation.
    let mut value: T = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    // SAFETY: InFrame requires the common header at offset zero.
    unsafe {
        std::ptr::addr_of_mut!(value)
            .cast::<InHead>()
            .write(in_head())
    };
    value
}
pub fn output<T: OutFrame>() -> T {
    // SAFETY: ABI outputs consist of plain C fields with a valid zero representation.
    let mut value: T = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    // SAFETY: OutFrame requires the common header at offset zero.
    unsafe {
        std::ptr::addr_of_mut!(value)
            .cast::<OutHead>()
            .write(out_head())
    };
    value
}
pub fn called(call: &Called) -> String {
    let text = call
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} lease={} {text}", call.outcome, call.lease != 0)
}
pub fn bind(dispatcher: &Dispatcher, instance: &str) -> Bind {
    Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::NoNeeds,
    }
}
pub fn cdylib() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("test executable path");
    let profile = exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("target profile");
    let filename = busbar_plugin_loader::plugin_library_filename("busbar_transport_webrtc_plugin");
    let artifact = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| profile.join(filename));
    assert!(
        artifact.is_absolute(),
        "BUSBAR_PLUGIN_CDYLIB must be absolute"
    );
    assert!(
        artifact.is_file(),
        "build the actual WebRTC cdylib before testing: {}",
        artifact.display()
    );
    artifact
}
pub fn open(plugin: &Plugin<Transport>) -> Called {
    let mut frame: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    frame.input.settings = Blob {
        ptr: b"{}".as_ptr(),
        len: 2,
        fmt: BLOB_JSON,
        flags: 0,
    };
    frame.input.generation = 1;
    plugin.call(life::OPEN, &mut frame)
}
pub fn validate(plugin: &Plugin<Transport>) -> Called {
    let mut error = [0; 512];
    let mut frame: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    frame.input.settings = Blob {
        ptr: b"{}".as_ptr(),
        len: 2,
        fmt: BLOB_JSON,
        flags: 0,
    };
    frame.input.err_buf = error.as_mut_ptr();
    frame.input.err_cap = error.len();
    plugin.call(life::VALIDATE, &mut frame)
}
pub fn close(plugin: &Plugin<Transport>) -> Called {
    let mut frame: Frame<InHead, OutHead> = Frame::new(input(), output());
    plugin.call(life::CLOSE, &mut frame)
}
