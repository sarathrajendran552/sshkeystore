pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;
pub const RESERVED_CID: u32 = 0x0000_0000;

pub const CMD_PING: u8 = 0x01;
pub const CMD_INIT: u8 = 0x06;
pub const CMD_WINK: u8 = 0x08;
pub const CMD_CBOR: u8 = 0x10;
pub const CMD_CANCEL: u8 = 0x11;
pub const CMD_KEEPALIVE: u8 = 0x3B;
pub const CMD_ERROR: u8 = 0x3F;

pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const ERR_OTHER: u8 = 0x7F;

pub const CAP_CBOR: u8 = 0x04;
pub const CAP_NMSG: u8 = 0x08;
pub const CAPABILITIES: u8 = CAP_CBOR | CAP_NMSG;

pub const INIT_DATA_SIZE: usize = 57;
pub const CONT_DATA_SIZE: usize = 59;
pub const MAX_CONT_PACKETS: usize = 128;
pub const MAX_MESSAGE_SIZE: usize = INIT_DATA_SIZE + (MAX_CONT_PACKETS * CONT_DATA_SIZE);
pub const CTAPHID_PROTOCOL_VERSION: u8 = 2;
