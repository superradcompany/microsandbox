//! Wire protocol between a sandbox's display server and `msb display`.
//!
//! Newline-delimited JSON over the sandbox's `display.sock`. Pixels never
//! cross the socket: each scanout has a file of `slots` back-to-back frames
//! that both sides map, and the server only announces which slot is fresh.

use serde::{Deserialize, Serialize};

/// Number of frame slots per scanout file. The device writes slot
/// `seq % SLOTS` while the viewer may still be reading the previous one.
pub const SLOTS: u32 = 2;

/// Range of the absolute pointer axes (`ABS_X`/`ABS_Y`), like QEMU's tablet.
pub const ABS_RANGE: u32 = 32767;

/// Messages from the sandbox to the viewer.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ServerMsg {
    /// First message on a connection.
    Hello { sandbox: String },
    /// A scanout is (re)configured; `path` holds `slots` frames of
    /// `width * height * 4` bytes in `format`.
    Configure {
        scanout: u32,
        width: u32,
        height: u32,
        format: String,
        path: String,
        slots: u32,
    },
    /// Slot `slot` of scanout `scanout` holds frame `seq`; `rect` is the
    /// damaged area `[x, y, width, height]` (the whole frame when absent).
    Frame {
        scanout: u32,
        slot: u32,
        seq: u64,
        rect: Option<[u32; 4]>,
    },
    /// The guest turned the scanout off.
    Disable { scanout: u32 },
}

/// Messages from the viewer to the sandbox: evdev-style input.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ViewerMsg {
    /// Keyboard key (`KEY_*` code) pressed or released.
    Key { code: u16, down: bool },
    /// Absolute pointer position in `0..=ABS_RANGE` on both axes.
    Abs { x: u32, y: u32 },
    /// Pointer button (`BTN_*` code) pressed or released.
    Btn { code: u16, down: bool },
    /// Relative axis event (`REL_WHEEL` etc.).
    Rel { code: u16, value: i32 },
}

/// Linux input event codes used by both ends (`<linux/input-event-codes.h>`).
#[allow(missing_docs)]
pub mod evdev {
    pub const EV_SYN: u16 = 0x00;
    pub const EV_KEY: u16 = 0x01;
    pub const EV_REL: u16 = 0x02;
    pub const EV_ABS: u16 = 0x03;
    pub const SYN_REPORT: u16 = 0x00;

    pub const REL_HWHEEL: u16 = 0x06;
    pub const REL_WHEEL: u16 = 0x08;
    pub const ABS_X: u16 = 0x00;
    pub const ABS_Y: u16 = 0x01;

    pub const BTN_LEFT: u16 = 0x110;
    pub const BTN_RIGHT: u16 = 0x111;
    pub const BTN_MIDDLE: u16 = 0x112;

    pub const BUS_VIRTUAL: u16 = 0x06;

    pub const KEY_ESC: u16 = 1;
    pub const KEY_1: u16 = 2;
    pub const KEY_2: u16 = 3;
    pub const KEY_3: u16 = 4;
    pub const KEY_4: u16 = 5;
    pub const KEY_5: u16 = 6;
    pub const KEY_6: u16 = 7;
    pub const KEY_7: u16 = 8;
    pub const KEY_8: u16 = 9;
    pub const KEY_9: u16 = 10;
    pub const KEY_0: u16 = 11;
    pub const KEY_MINUS: u16 = 12;
    pub const KEY_EQUAL: u16 = 13;
    pub const KEY_BACKSPACE: u16 = 14;
    pub const KEY_TAB: u16 = 15;
    pub const KEY_Q: u16 = 16;
    pub const KEY_W: u16 = 17;
    pub const KEY_E: u16 = 18;
    pub const KEY_R: u16 = 19;
    pub const KEY_T: u16 = 20;
    pub const KEY_Y: u16 = 21;
    pub const KEY_U: u16 = 22;
    pub const KEY_I: u16 = 23;
    pub const KEY_O: u16 = 24;
    pub const KEY_P: u16 = 25;
    pub const KEY_LEFTBRACE: u16 = 26;
    pub const KEY_RIGHTBRACE: u16 = 27;
    pub const KEY_ENTER: u16 = 28;
    pub const KEY_LEFTCTRL: u16 = 29;
    pub const KEY_A: u16 = 30;
    pub const KEY_S: u16 = 31;
    pub const KEY_D: u16 = 32;
    pub const KEY_F: u16 = 33;
    pub const KEY_G: u16 = 34;
    pub const KEY_H: u16 = 35;
    pub const KEY_J: u16 = 36;
    pub const KEY_K: u16 = 37;
    pub const KEY_L: u16 = 38;
    pub const KEY_SEMICOLON: u16 = 39;
    pub const KEY_APOSTROPHE: u16 = 40;
    pub const KEY_GRAVE: u16 = 41;
    pub const KEY_LEFTSHIFT: u16 = 42;
    pub const KEY_BACKSLASH: u16 = 43;
    pub const KEY_Z: u16 = 44;
    pub const KEY_X: u16 = 45;
    pub const KEY_C: u16 = 46;
    pub const KEY_V: u16 = 47;
    pub const KEY_B: u16 = 48;
    pub const KEY_N: u16 = 49;
    pub const KEY_M: u16 = 50;
    pub const KEY_COMMA: u16 = 51;
    pub const KEY_DOT: u16 = 52;
    pub const KEY_SLASH: u16 = 53;
    pub const KEY_RIGHTSHIFT: u16 = 54;
    pub const KEY_KPASTERISK: u16 = 55;
    pub const KEY_LEFTALT: u16 = 56;
    pub const KEY_SPACE: u16 = 57;
    pub const KEY_CAPSLOCK: u16 = 58;
    pub const KEY_F1: u16 = 59;
    pub const KEY_F2: u16 = 60;
    pub const KEY_F3: u16 = 61;
    pub const KEY_F4: u16 = 62;
    pub const KEY_F5: u16 = 63;
    pub const KEY_F6: u16 = 64;
    pub const KEY_F7: u16 = 65;
    pub const KEY_F8: u16 = 66;
    pub const KEY_F9: u16 = 67;
    pub const KEY_F10: u16 = 68;
    pub const KEY_NUMLOCK: u16 = 69;
    pub const KEY_SCROLLLOCK: u16 = 70;
    pub const KEY_KP7: u16 = 71;
    pub const KEY_KP8: u16 = 72;
    pub const KEY_KP9: u16 = 73;
    pub const KEY_KPMINUS: u16 = 74;
    pub const KEY_KP4: u16 = 75;
    pub const KEY_KP5: u16 = 76;
    pub const KEY_KP6: u16 = 77;
    pub const KEY_KPPLUS: u16 = 78;
    pub const KEY_KP1: u16 = 79;
    pub const KEY_KP2: u16 = 80;
    pub const KEY_KP3: u16 = 81;
    pub const KEY_KP0: u16 = 82;
    pub const KEY_KPDOT: u16 = 83;
    pub const KEY_102ND: u16 = 86;
    pub const KEY_F11: u16 = 87;
    pub const KEY_F12: u16 = 88;
    pub const KEY_KPENTER: u16 = 96;
    pub const KEY_RIGHTCTRL: u16 = 97;
    pub const KEY_KPSLASH: u16 = 98;
    pub const KEY_SYSRQ: u16 = 99;
    pub const KEY_RIGHTALT: u16 = 100;
    pub const KEY_HOME: u16 = 102;
    pub const KEY_UP: u16 = 103;
    pub const KEY_PAGEUP: u16 = 104;
    pub const KEY_LEFT: u16 = 105;
    pub const KEY_RIGHT: u16 = 106;
    pub const KEY_END: u16 = 107;
    pub const KEY_DOWN: u16 = 108;
    pub const KEY_PAGEDOWN: u16 = 109;
    pub const KEY_INSERT: u16 = 110;
    pub const KEY_DELETE: u16 = 111;
    pub const KEY_MUTE: u16 = 113;
    pub const KEY_VOLUMEDOWN: u16 = 114;
    pub const KEY_VOLUMEUP: u16 = 115;
    pub const KEY_KPEQUAL: u16 = 117;
    pub const KEY_PAUSE: u16 = 119;
    pub const KEY_LEFTMETA: u16 = 125;
    pub const KEY_RIGHTMETA: u16 = 126;
    pub const KEY_COMPOSE: u16 = 127;
    pub const KEY_MENU: u16 = 139;
    pub const KEY_PRINT: u16 = 210;

    /// Every key the virtual keyboard advertises.
    pub const KEYBOARD_KEYS: &[u16] = &[
        KEY_ESC, KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, KEY_7, KEY_8, KEY_9, KEY_0,
        KEY_MINUS, KEY_EQUAL, KEY_BACKSPACE, KEY_TAB, KEY_Q, KEY_W, KEY_E, KEY_R, KEY_T,
        KEY_Y, KEY_U, KEY_I, KEY_O, KEY_P, KEY_LEFTBRACE, KEY_RIGHTBRACE, KEY_ENTER,
        KEY_LEFTCTRL, KEY_A, KEY_S, KEY_D, KEY_F, KEY_G, KEY_H, KEY_J, KEY_K, KEY_L,
        KEY_SEMICOLON, KEY_APOSTROPHE, KEY_GRAVE, KEY_LEFTSHIFT, KEY_BACKSLASH, KEY_Z,
        KEY_X, KEY_C, KEY_V, KEY_B, KEY_N, KEY_M, KEY_COMMA, KEY_DOT, KEY_SLASH,
        KEY_RIGHTSHIFT, KEY_KPASTERISK, KEY_LEFTALT, KEY_SPACE, KEY_CAPSLOCK, KEY_F1,
        KEY_F2, KEY_F3, KEY_F4, KEY_F5, KEY_F6, KEY_F7, KEY_F8, KEY_F9, KEY_F10,
        KEY_NUMLOCK, KEY_SCROLLLOCK, KEY_KP7, KEY_KP8, KEY_KP9, KEY_KPMINUS, KEY_KP4,
        KEY_KP5, KEY_KP6, KEY_KPPLUS, KEY_KP1, KEY_KP2, KEY_KP3, KEY_KP0, KEY_KPDOT,
        KEY_102ND, KEY_F11, KEY_F12, KEY_KPENTER, KEY_RIGHTCTRL, KEY_KPSLASH, KEY_SYSRQ,
        KEY_RIGHTALT, KEY_HOME, KEY_UP, KEY_PAGEUP, KEY_LEFT, KEY_RIGHT, KEY_END, KEY_DOWN,
        KEY_PAGEDOWN, KEY_INSERT, KEY_DELETE, KEY_MUTE, KEY_VOLUMEDOWN, KEY_VOLUMEUP,
        KEY_KPEQUAL, KEY_PAUSE, KEY_LEFTMETA, KEY_RIGHTMETA, KEY_COMPOSE, KEY_MENU, KEY_PRINT,
    ];
}
