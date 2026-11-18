use super::types::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CHANNELS: usize = 8;

pub enum ChannelState {
    Idle {
        last_activity: Instant,
    },
    Receiving {
        cmd: u8,
        bcnt: u16,
        data: Vec<u8>,
        next_seq: u8,
        deadline: Instant,
    },
}

pub struct Message {
    pub cid: u32,
    pub cmd: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel busy")]
    Busy,
    #[error("invalid channel")]
    InvalidChannel,
    #[error("unexpected continuation packet")]
    UnexpectedCont,
    #[error("invalid message length")]
    InvalidLen,
    #[error("invalid sequence number")]
    InvalidSeq,
    #[error("channel timeout")]
    Timeout,
}

pub struct ChannelManager {
    channels: HashMap<u32, ChannelState>,
    rng: StdRng,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            rng: StdRng::from_entropy(),
        }
    }

    pub fn allocate(&mut self) -> Result<u32, ChannelError> {
        self.reap();
        if self.channels.len() >= MAX_CHANNELS {
            return Err(ChannelError::Busy);
        }
        loop {
            let cid: u32 = self.rng.r#gen();
            if cid != RESERVED_CID && cid != BROADCAST_CID && !self.channels.contains_key(&cid) {
                self.channels.insert(
                    cid,
                    ChannelState::Idle {
                        last_activity: Instant::now(),
                    },
                );
                return Ok(cid);
            }
        }
    }

    pub fn exists(&self, cid: u32) -> bool {
        self.channels.contains_key(&cid)
    }

    pub fn set_idle(&mut self, cid: u32) {
        if let Some(state) = self.channels.get_mut(&cid) {
            *state = ChannelState::Idle {
                last_activity: Instant::now(),
            };
        }
    }

    pub fn remove(&mut self, cid: u32) {
        self.channels.remove(&cid);
    }

    fn reap(&mut self) {
        self.channels.retain(|_, state| match state {
            ChannelState::Idle { last_activity } => last_activity.elapsed() < CHANNEL_TIMEOUT,
            ChannelState::Receiving { deadline, .. } => Instant::now() < *deadline,
        });
    }

    pub fn feed_init(
        &mut self,
        cid: u32,
        cmd: u8,
        bcnt: u16,
        data: Vec<u8>,
    ) -> Result<Option<Message>, ChannelError> {
        if bcnt as usize > MAX_MESSAGE_SIZE {
            return Err(ChannelError::InvalidLen);
        }

        if cid == BROADCAST_CID {
            let payload = data[..(bcnt as usize).min(data.len())].to_vec();
            return Ok(Some(Message { cid, cmd, payload }));
        }

        if !self.channels.contains_key(&cid) {
            return Err(ChannelError::InvalidChannel);
        }

        if bcnt as usize <= INIT_DATA_SIZE {
            let payload = data[..bcnt as usize].to_vec();
            self.set_idle(cid);
            return Ok(Some(Message { cid, cmd, payload }));
        }

        self.channels.insert(
            cid,
            ChannelState::Receiving {
                cmd,
                bcnt,
                data,
                next_seq: 0,
                deadline: Instant::now() + CHANNEL_TIMEOUT,
            },
        );
        Ok(None)
    }

    pub fn feed_cont(
        &mut self,
        cid: u32,
        seq: u8,
        new_data: Vec<u8>,
    ) -> Result<Option<Message>, ChannelError> {
        let timed_out = match self.channels.get(&cid) {
            None => return Err(ChannelError::InvalidChannel),
            Some(ChannelState::Receiving { deadline, .. }) => Instant::now() > *deadline,
            Some(_) => return Err(ChannelError::UnexpectedCont),
        };

        if timed_out {
            self.remove(cid);
            return Err(ChannelError::Timeout);
        }

        let (cmd, bcnt, complete) = match self.channels.get_mut(&cid) {
            Some(ChannelState::Receiving {
                cmd,
                bcnt,
                data,
                next_seq,
                ..
            }) => {
                if seq != *next_seq {
                    return Err(ChannelError::InvalidSeq);
                }
                *next_seq = next_seq.wrapping_add(1);
                data.extend_from_slice(&new_data);
                (*cmd, *bcnt, data.len() >= *bcnt as usize)
            }
            _ => unreachable!(),
        };

        if complete {
            let payload = match self.channels.get(&cid) {
                Some(ChannelState::Receiving { data, .. }) => data[..bcnt as usize].to_vec(),
                _ => unreachable!(),
            };
            self.set_idle(cid);
            Ok(Some(Message { cid, cmd, payload }))
        } else {
            Ok(None)
        }
    }
}
