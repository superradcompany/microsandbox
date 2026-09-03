// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
use vm_memory::{ByteValued, Le32, Le64};

// virtqueues

pub const CONTROL_QUEUE_IDX: u16 = 0;
pub const EVENT_QUEUE_IDX: u16 = 1;
pub const TX_QUEUE_IDX: u16 = 2;
pub const RX_QUEUE_IDX: u16 = 3;
pub const NUM_QUEUES: u16 = 4;

// jack control request types

pub const VIRTIO_SND_R_JACK_INFO: u32 = 1;
pub const VIRTIO_SND_R_JACK_REMAP: u32 = 2;

// PCM control request types

pub const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
pub const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
pub const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x0102;
pub const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x0103;
pub const VIRTIO_SND_R_PCM_START: u32 = 0x0104;
pub const VIRTIO_SND_R_PCM_STOP: u32 = 0x0105;

// channel map control request types

pub const VIRTIO_SND_R_CHMAP_INFO: u32 = 0x0200;

// jack event types

pub const VIRTIO_SND_EVT_JACK_CONNECTED: u32 = 0x1000;
pub const VIRTIO_SND_EVT_JACK_DISCONNECTED: u32 = 0x1001;

// PCM event types

pub const VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED: u32 = 0x1100;
pub const VIRTIO_SND_EVT_PCM_XRUN: u32 = 0x1101;

// common status codes

pub const VIRTIO_SND_S_OK: u32 = 0x8000;
pub const VIRTIO_SND_S_BAD_MSG: u32 = 0x8001;
pub const VIRTIO_SND_S_NOT_SUPP: u32 = 0x8002;
pub const VIRTIO_SND_S_IO_ERR: u32 = 0x8003;

// device data flow directions

pub const VIRTIO_SND_D_OUTPUT: u8 = 0;
pub const VIRTIO_SND_D_INPUT: u8 = 1;

// supported jack features

pub const VIRTIO_SND_JACK_F_REMAP: u32 = 0;

// supported PCM stream features

pub const VIRTIO_SND_PCM_F_SHMEM_HOST: u8 = 0;
pub const VIRTIO_SND_PCM_F_SHMEM_GUEST: u8 = 1;
pub const VIRTIO_SND_PCM_F_MSG_POLLING: u8 = 2;
pub const VIRTIO_SND_PCM_F_EVT_SHMEM_PERIODS: u8 = 3;
pub const VIRTIO_SND_PCM_F_EVT_XRUNS: u8 = 4;

// supported PCM sample formats

pub const VIRTIO_SND_PCM_FMT_IMA_ADPCM: u8 = 0;
pub const VIRTIO_SND_PCM_FMT_MU_LAW: u8 = 1;
pub const VIRTIO_SND_PCM_FMT_A_LAW: u8 = 2;
pub const VIRTIO_SND_PCM_FMT_S8: u8 = 3;
pub const VIRTIO_SND_PCM_FMT_U8: u8 = 4;
pub const VIRTIO_SND_PCM_FMT_S16: u8 = 5;
pub const VIRTIO_SND_PCM_FMT_U16: u8 = 6;
pub const VIRTIO_SND_PCM_FMT_S18_3: u8 = 7;
pub const VIRTIO_SND_PCM_FMT_U18_3: u8 = 8;
pub const VIRTIO_SND_PCM_FMT_S20_3: u8 = 9;
pub const VIRTIO_SND_PCM_FMT_U20_3: u8 = 10;
pub const VIRTIO_SND_PCM_FMT_S24_3: u8 = 11;
pub const VIRTIO_SND_PCM_FMT_U24_3: u8 = 12;
pub const VIRTIO_SND_PCM_FMT_S20: u8 = 13;
pub const VIRTIO_SND_PCM_FMT_U20: u8 = 14;
pub const VIRTIO_SND_PCM_FMT_S24: u8 = 15;
pub const VIRTIO_SND_PCM_FMT_U24: u8 = 16;
pub const VIRTIO_SND_PCM_FMT_S32: u8 = 17;
pub const VIRTIO_SND_PCM_FMT_U32: u8 = 18;
pub const VIRTIO_SND_PCM_FMT_FLOAT: u8 = 19;
pub const VIRTIO_SND_PCM_FMT_FLOAT64: u8 = 20;
// digital formats (width / physical width)
pub const VIRTIO_SND_PCM_FMT_DSD_U8: u8 = 21;
pub const VIRTIO_SND_PCM_FMT_DSD_U16: u8 = 22;
pub const VIRTIO_SND_PCM_FMT_DSD_U32: u8 = 23;
pub const VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME: u8 = 24;
pub(crate) const _VIRTIO_SND_PCM_FMT_MAX: u8 = 25;

// supported PCM frame rates

pub const VIRTIO_SND_PCM_RATE_5512: u8 = 0;
pub const VIRTIO_SND_PCM_RATE_8000: u8 = 1;
pub const VIRTIO_SND_PCM_RATE_11025: u8 = 2;
pub const VIRTIO_SND_PCM_RATE_16000: u8 = 3;
pub const VIRTIO_SND_PCM_RATE_22050: u8 = 4;
pub const VIRTIO_SND_PCM_RATE_32000: u8 = 5;
pub const VIRTIO_SND_PCM_RATE_44100: u8 = 6;
pub const VIRTIO_SND_PCM_RATE_48000: u8 = 7;
pub const VIRTIO_SND_PCM_RATE_64000: u8 = 8;
pub const VIRTIO_SND_PCM_RATE_88200: u8 = 9;
pub const VIRTIO_SND_PCM_RATE_96000: u8 = 10;
pub const VIRTIO_SND_PCM_RATE_176400: u8 = 11;
pub const VIRTIO_SND_PCM_RATE_192000: u8 = 12;
pub const VIRTIO_SND_PCM_RATE_384000: u8 = 13;
pub(crate) const _VIRTIO_SND_PCM_RATE_MAX: u8 = 14;

// standard channel position definition

pub const VIRTIO_SND_CHMAP_NONE: u8 = 0; /* undefined */
pub const VIRTIO_SND_CHMAP_NA: u8 = 1; /* silent */
pub const VIRTIO_SND_CHMAP_MONO: u8 = 2; /* mono stream */
pub const VIRTIO_SND_CHMAP_FL: u8 = 3; /* front left */
pub const VIRTIO_SND_CHMAP_FR: u8 = 4; /* front right */
pub const VIRTIO_SND_CHMAP_RL: u8 = 5; /* rear left */
pub const VIRTIO_SND_CHMAP_RR: u8 = 6; /* rear right */
pub const VIRTIO_SND_CHMAP_FC: u8 = 7; /* front center */
pub const VIRTIO_SND_CHMAP_LFE: u8 = 8; /* low frequency (LFE) */
pub const VIRTIO_SND_CHMAP_SL: u8 = 9; /* side left */
pub const VIRTIO_SND_CHMAP_SR: u8 = 10; /* side right */
pub const VIRTIO_SND_CHMAP_RC: u8 = 11; /* rear center */
pub const VIRTIO_SND_CHMAP_FLC: u8 = 12; /* front left center */
pub const VIRTIO_SND_CHMAP_FRC: u8 = 13; /* front right center */
pub const VIRTIO_SND_CHMAP_RLC: u8 = 14; /* rear left center */
pub const VIRTIO_SND_CHMAP_RRC: u8 = 15; /* rear right center */
pub const VIRTIO_SND_CHMAP_FLW: u8 = 16; /* front left wide */
pub const VIRTIO_SND_CHMAP_FRW: u8 = 17; /* front right wide */
pub const VIRTIO_SND_CHMAP_FLH: u8 = 18; /* front left high */
pub const VIRTIO_SND_CHMAP_FCH: u8 = 19; /* front center high */
pub const VIRTIO_SND_CHMAP_FRH: u8 = 20; /* front right high */
pub const VIRTIO_SND_CHMAP_TC: u8 = 21; /* top center */
pub const VIRTIO_SND_CHMAP_TFL: u8 = 22; /* top front left */
pub const VIRTIO_SND_CHMAP_TFR: u8 = 23; /* top front right */
pub const VIRTIO_SND_CHMAP_TFC: u8 = 24; /* top front center */
pub const VIRTIO_SND_CHMAP_TRL: u8 = 25; /* top rear left */
pub const VIRTIO_SND_CHMAP_TRR: u8 = 26; /* top rear right */
pub const VIRTIO_SND_CHMAP_TRC: u8 = 27; /* top rear center */
pub const VIRTIO_SND_CHMAP_TFLC: u8 = 28; /* top front left center */
pub const VIRTIO_SND_CHMAP_TFRC: u8 = 29; /* top front right center */
pub const VIRTIO_SND_CHMAP_TSL: u8 = 34; /* top side left */
pub const VIRTIO_SND_CHMAP_TSR: u8 = 35; /* top side right */
pub const VIRTIO_SND_CHMAP_LLFE: u8 = 36; /* left LFE */
pub const VIRTIO_SND_CHMAP_RLFE: u8 = 37; /* right LFE */
pub const VIRTIO_SND_CHMAP_BC: u8 = 38; /* bottom center */
pub const VIRTIO_SND_CHMAP_BLC: u8 = 39; /* bottom left center */
pub const VIRTIO_SND_CHMAP_BRC: u8 = 40; /* bottom right center */
// maximum possible number of channels
pub const VIRTIO_SND_CHMAP_MAX_SIZE: usize = 18;

/// Virtio Sound Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundConfig {
    /// total number of all available jacks
    pub jacks: Le32,
    /// total number of all available PCM streams
    pub streams: Le32,
    /// total number of all available channel maps
    pub chmaps: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundConfig {}

/// Virtio Sound Request / Response common header
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundHeader {
    /// request type / response status
    pub code: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundHeader {}

/// Virtio Sound event notification
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundEvent {
    /// PCM stream event type
    pub hdr: VirtioSoundHeader,
    /// PCM stream identifier from 0 to streams - 1
    pub data: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundEvent {}

/// Virtio Sound request information about any kind of configuration item
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundQueryInfo {
    /// item request type (VIRTIO_SND_R_*_INFO)
    pub hdr: VirtioSoundHeader,
    /// starting identifier for the item
    pub start_id: Le32,
    /// number of items for which information is requested
    pub count: Le32,
    /// size of the structure containing information for one item
    pub size: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundQueryInfo {}

/// Virtio Sound response common information header
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundInfo {
    /// function group node identifier
    pub hda_fn_nid: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundInfo {}

/// Jack control request / Jack common header
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundJackHeader {
    /// jack request type (VIRTIO_SND_R_JACK_*)
    pub hdr: VirtioSoundHeader,
    /// jack identifier
    pub jack_id: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundJackHeader {}

/// Jack response information about available jacks
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundJackInfo {
    /// jack response header type
    pub hdr: VirtioSoundInfo,
    /// supported feature bit map (VIRTIO_SND_JACK_F_XXX)
    pub feature: Le32,
    /// pin default configuration value
    pub hda_reg_defconf: Le32,
    /// pin capabilities value
    pub hda_reg_caps: Le32,
    /// current jack connection status
    pub connected: u8,
    pub padding: [u8; 7],
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundJackInfo {}

///If the VIRTIO_SND_JACK_F_REMAP feature bit is set in the jack information
/// Remap control request
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundJackRemap {
    pub hdr: VirtioSoundJackHeader, /* .code = VIRTIO_SND_R_JACK_REMAP */
    pub association: Le32,
    pub sequence: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundJackRemap {}

/// PCM control request / PCM common header
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundPcmHeader {
    pub hdr: VirtioSoundHeader,
    pub stream_id: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundPcmHeader {}

/// PCM response information
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundPcmInfo {
    pub hdr: VirtioSoundInfo,
    pub features: Le32, /* 1 << VIRTIO_SND_PCM_F_XXX */
    pub formats: Le64,  /* 1 << VIRTIO_SND_PCM_FMT_XXX */
    pub rates: Le64,    /* 1 << VIRTIO_SND_PCM_RATE_XXX */
    pub direction: u8,
    pub channels_min: u8,
    pub channels_max: u8,

    pub padding: [u8; 5],
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundPcmInfo {}

/// Set selected stream parameters for the specified stream ID
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSndPcmSetParams {
    pub hdr: VirtioSoundPcmHeader,
    pub buffer_bytes: Le32,
    pub period_bytes: Le32,
    pub features: Le32, /* 1 << VIRTIO_SND_PCM_F_XXX */
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
    pub padding: u8,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSndPcmSetParams {}

/// PCM I/O header
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundPcmXfer {
    pub stream_id: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundPcmXfer {}

/// PCM I/O status
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundPcmStatus {
    pub status: Le32,
    pub latency_bytes: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundPcmStatus {}

/// channel maps response information
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSoundChmapInfo {
    pub hdr: VirtioSoundInfo,
    pub direction: u8,
    pub channels: u8,
    pub positions: [u8; VIRTIO_SND_CHMAP_MAX_SIZE],
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundChmapInfo {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_virtiosound_structs_debug() {
        let val = VirtioSoundConfig::default();

        let debug_output = format!("{:?}", val);
        let expected_debug =
            "VirtioSoundConfig { jacks: Le32(0), streams: Le32(0), chmaps: Le32(0) }".to_string();
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundHeader::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = "VirtioSoundHeader { code: Le32(0) }".to_string();
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundEvent::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = format!("VirtioSoundEvent {{ hdr: {:?}, data: Le32(0) }}", val.hdr);

        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundQueryInfo::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = format!(
            "VirtioSoundQueryInfo {{ hdr: {:?}, start_id: Le32(0), count: Le32(0), size: Le32(0) \
             }}",
            val.hdr
        );
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundInfo::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = "VirtioSoundInfo { hda_fn_nid: Le32(0) }".to_string();
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundJackHeader::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = format!(
            "VirtioSoundJackHeader {{ hdr: {:?}, jack_id: Le32(0) }}",
            val.hdr
        );
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundJackInfo::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = format!(
            "VirtioSoundJackInfo {{ hdr: {:?}, feature: Le32(0), hda_reg_defconf: Le32(0), \
             hda_reg_caps: Le32(0), connected: 0, padding: {:?} }}",
            val.hdr, val.padding
        );
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundJackRemap::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = format!(
            "VirtioSoundJackRemap {{ hdr: {:?}, association: Le32(0), sequence: Le32(0) }}",
            val.hdr
        );
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundPcmHeader::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = format!(
            "VirtioSoundPcmHeader {{ hdr: {:?}, stream_id: Le32(0) }}",
            val.hdr
        );
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundPcmInfo::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = format!(
            "VirtioSoundPcmInfo {{ hdr: {:?}, features: Le32(0), formats: Le64(0), rates: \
             Le64(0), direction: 0, channels_min: 0, channels_max: 0, padding: {:?} }}",
            val.hdr, val.padding
        );
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSndPcmSetParams::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = format!(
            "VirtioSndPcmSetParams {{ hdr: {:?}, buffer_bytes: Le32(0), period_bytes: Le32(0), \
             features: Le32(0), channels: 0, format: 0, rate: 0, padding: 0 }}",
            val.hdr
        );
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundPcmXfer::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = "VirtioSoundPcmXfer { stream_id: Le32(0) }".to_string();
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundPcmStatus::default();

        let debug_output = format!("{:?}", val);
        let expected_debug =
            "VirtioSoundPcmStatus { status: Le32(0), latency_bytes: Le32(0) }".to_string();
        assert_eq!(debug_output, expected_debug);

        let val = VirtioSoundChmapInfo::default();

        let debug_output = format!("{:?}", val);
        let expected_debug = format!(
            "VirtioSoundChmapInfo {{ hdr: {:?}, direction: 0, channels: 0, positions: {:?} }}",
            val.hdr, val.positions
        );
        assert_eq!(debug_output, expected_debug);
    }
    #[test]
    fn test_virtiosound_structs_clone() {
        let val = VirtioSoundConfig::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundHeader::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundEvent::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundQueryInfo::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundInfo::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundJackHeader::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundJackInfo::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundJackRemap::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundPcmHeader::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundPcmInfo::default();
        assert_eq!(val, val.clone());

        let val = VirtioSndPcmSetParams::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundPcmXfer::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundPcmStatus::default();
        assert_eq!(val, val.clone());

        let val = VirtioSoundChmapInfo::default();
        assert_eq!(val, val.clone());
    }
}
