use super::report::FIDO_HID_REPORT_DESCRIPTOR;
use super::HidError;
use std::fs::{File, OpenOptions};
use std::io::Write;
use uhid_virt::{Bus, CreateParams, InputEvent, UHID_EVENT_SIZE};

/// Open /dev/uhid and register a virtual FIDO2 HID device.
pub fn create_uhid_device() -> Result<File, HidError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/uhid")
        .map_err(HidError::Create)?;

    let params = CreateParams {
        name: String::from("sshkeystore FIDO2"),
        phys: String::new(),
        uniq: String::new(),
        bus: Bus::USB,
        vendor: 0x1209,
        product: 0x5353,
        version: 0,
        country: 0,
        rd_data: FIDO_HID_REPORT_DESCRIPTOR.to_vec(),
    };

    let event: [u8; UHID_EVENT_SIZE] = InputEvent::Create(params).into();
    file.write_all(&event).map_err(HidError::Create)?;
    Ok(file)
}
