mod device;
mod report;
mod transport;

use std::io;

pub use transport::start_hid_transport;

#[derive(Debug, thiserror::Error)]
pub enum HidError {
    #[error("failed to create UHID device: {0}")]
    Create(io::Error),
    #[error("HID read error: {0}")]
    Read(String),
}
