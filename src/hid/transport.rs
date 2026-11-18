use super::device::create_uhid_device;
use super::report::HID_REPORT_SIZE;
use super::HidError;
use std::io::{Read, Write};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use uhid_virt::{InputEvent, OutputEvent, UHID_EVENT_SIZE};

pub struct HidTransport {
    pub incoming_rx: mpsc::Receiver<[u8; HID_REPORT_SIZE]>,
    pub outgoing_tx: mpsc::Sender<[u8; HID_REPORT_SIZE]>,
    pub task: JoinHandle<Result<(), HidError>>,
}

pub fn start_hid_transport() -> Result<HidTransport, HidError> {
    let (incoming_tx, incoming_rx) = mpsc::channel::<[u8; HID_REPORT_SIZE]>(64);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<[u8; HID_REPORT_SIZE]>(64);

    let task = tokio::task::spawn_blocking(move || {
        let mut file = create_uhid_device()?;
        tracing::info!("virtual FIDO2 UHID device registered");

        // A dedicated writer thread is required: the reader may block waiting
        // for the next host event while the host waits for our response.
        let mut write_file = file.try_clone().map_err(HidError::Create)?;
        std::thread::spawn(move || {
            while let Some(report) = outgoing_rx.blocking_recv() {
                let event: [u8; UHID_EVENT_SIZE] = InputEvent::Input { data: &report }.into();
                if let Err(e) = write_file.write_all(&event) {
                    tracing::error!("HID write error: {e}");
                    break;
                }
                let hex: String = report.iter().take(24).map(|b| format!("{b:02x}")).collect();
                tracing::trace!(head = %hex, "HID tx");
            }
        });

        let mut buf = [0u8; UHID_EVENT_SIZE];
        loop {
            file.read_exact(&mut buf)
                .map_err(|e| HidError::Read(e.to_string()))?;

            let event = match OutputEvent::try_from(buf) {
                Ok(event) => event,
                Err(uhid_virt::StreamError::UnknownEventType(t)) => {
                    tracing::debug!("ignoring unknown UHID event type {t}");
                    continue;
                }
                Err(uhid_virt::StreamError::Io(e)) => {
                    return Err(HidError::Read(e.to_string()));
                }
            };

            match event {
                OutputEvent::Output { data } => {
                    // hidraw may prepend a 0x00 report-ID byte.
                    let stripped = data.len() == HID_REPORT_SIZE + 1 && data[0] == 0;
                    let payload = if stripped { &data[1..] } else { &data[..] };
                    let mut report = [0u8; HID_REPORT_SIZE];
                    let len = payload.len().min(HID_REPORT_SIZE);
                    report[..len].copy_from_slice(&payload[..len]);
                    if incoming_tx.blocking_send(report).is_err() {
                        break;
                    }
                }
                OutputEvent::Open => tracing::info!("HID device opened by host"),
                OutputEvent::Close => tracing::info!("HID device closed by host"),
                OutputEvent::Start { dev_flags: _ } => tracing::debug!("HID device started"),
                OutputEvent::Stop => {
                    tracing::info!("HID device stopped");
                    break;
                }
                OutputEvent::GetReport { .. } => tracing::debug!("HID GetReport ignored"),
                OutputEvent::SetReport { .. } => tracing::debug!("HID SetReport ignored"),
            }
        }
        Ok(())
    });

    Ok(HidTransport {
        incoming_rx,
        outgoing_tx,
        task,
    })
}
