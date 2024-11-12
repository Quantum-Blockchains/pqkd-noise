#[cfg(feature = "risky-raw-split")]
use crate::constants::{CIPHERKEYLEN, MAXHASHLEN};
#[cfg(feature = "hfs")]
use crate::constants::{MAXKEMCTLEN, MAXKEMPUBLEN, MAXKEMSSLEN};
#[cfg(feature = "hfs")]
use crate::types::Kem;
use crate::{
    cipherstate::CipherStates,
    constants::{MAXDHLEN, MAXMSGLEN, TAGLEN},
    error::{Error, StateProblem},
    stateless_transportstate::StatelessTransportState,
    // symmetricstate::SymmetricState,
    transportstate::TransportState,
    types::Dh,
    utils::Toggle,
};
use base64::prelude::*;
use pqkd;
use std::{convert::TryInto, fmt};

/// A state machine encompassing the handshake phase of a Noise session.
///
/// **Note:** you are probably looking for [`Builder`](struct.Builder.html) to
/// get started.
///
/// See: https://noiseprotocol.org/noise.html#the-handshakestate-object
pub struct HandshakeState {
    pub(crate) cipherstates: CipherStates,
    pub(crate) s: Toggle<Box<dyn Dh>>,
    pub(crate) rs: Toggle<[u8; MAXDHLEN]>,
    pub(crate) initiator: bool,
    pub(crate) my_turn: bool,
    pub(crate) number_of_turn: usize,
    pub(crate) pattern_position: usize,
    pub(crate) pqkd: pqkd::PqkdClient,
    pub(crate) local_sae_id: Vec<u8>,
    pub(crate) remote_sae_id: Option<Vec<u8>>,
    pub(crate) local_key_id: Option<Vec<u8>>,
    pub(crate) remote_key_id: Option<Vec<u8>>,
    pub(crate) remote_enc_key: Option<Vec<u8>>,
}

impl HandshakeState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        s: Toggle<Box<dyn Dh>>,
        rs: Toggle<[u8; MAXDHLEN]>,
        initiator: bool,
        cipherstates: CipherStates,
        sae_id: String,
        addr_pqkd: String,
    ) -> Result<HandshakeState, Error> {
        let pqkd = pqkd::BuilderPqkdClient::with_addr(&addr_pqkd)
            .unwrap()
            .with_local_sae_id(&sae_id)
            .build();

        Ok(HandshakeState {
            cipherstates,
            s,
            rs,
            initiator,
            my_turn: initiator,
            number_of_turn: 5,
            pattern_position: 0,
            pqkd,
            local_sae_id: sae_id.as_bytes().to_vec(),
            remote_sae_id: None,
            local_key_id: None,
            remote_key_id: None,
            remote_enc_key: None,
        })
    }

    pub(crate) fn dh_len(&self) -> usize {
        self.s.pub_len()
    }

    /// DOC
    pub async fn enc_key(&mut self) -> Result<(), Error> {
        if self.remote_sae_id.is_none() {
            return Err(Error::Input);
        }
        let s = self.remote_sae_id.clone().unwrap();
        let sae_id = std::str::from_utf8(s.as_slice()).unwrap();
        let key = self.pqkd.enc_keys(sae_id).size(256).send().await.unwrap().keys();
        let key_dec = BASE64_STANDARD.decode(key[0].key()).unwrap();
        if self.is_initiator() {
            self.cipherstates.0.set(key_dec.as_slice(), 0);
        } else {
            self.cipherstates.1.set(key_dec.as_slice(), 0);
        }
        let key_id = key[0].key_id();
        self.local_key_id = Some(key_id.as_bytes().to_vec());
        Ok(())
    }

    /// DOC
    pub async fn dec_key(&mut self) -> Result<(), Error> {
        if self.remote_sae_id.is_none() {
            return Err(Error::Input);
        }
        if self.remote_key_id.is_none() {
            return Err(Error::Input);
        }
        let sae_id = self.remote_sae_id.clone().unwrap();
        let key_id = self.remote_key_id.clone().unwrap();
        let sae_id = std::str::from_utf8(sae_id.as_slice()).unwrap();
        let key_id = std::str::from_utf8(key_id.as_slice()).unwrap();
        let key = self.pqkd.dec_keys(sae_id).key_id(key_id).send().await.unwrap().keys();
        let key_dec = BASE64_STANDARD.decode(key[0].key()).unwrap();
        if !self.is_initiator() {
            self.cipherstates.0.set(key_dec.as_slice(), 0);
        } else {
            self.cipherstates.1.set(key_dec.as_slice(), 0);
        }
        Ok(())
    }

    fn _write_sae_id(&self, mut byte_index: usize, message: &mut [u8]) -> Result<usize, Error> {
        // get local sae id from local pqkd
        let local_sae_id = self.local_sae_id.clone();
        // convert len of local sae id to 16 bit
        let local_sae_id_len =
            &[(local_sae_id.len() >> 8) as u8, (local_sae_id.len() & 0xff) as u8];
        // check len of message
        if byte_index + local_sae_id_len.len() + local_sae_id.len() > message.len() {
            return Err(Error::Input);
        }
        message[byte_index..byte_index + local_sae_id_len.len()].copy_from_slice(local_sae_id_len);
        byte_index += local_sae_id_len.len();
        message[byte_index..byte_index + local_sae_id.len()]
            .copy_from_slice(local_sae_id.as_slice());
        byte_index += local_sae_id.len();
        Ok(byte_index)
    }

    fn _write_key_id(&mut self, mut byte_index: usize, message: &mut [u8]) -> Result<usize, Error> {
        if self.local_key_id.is_none() {
            return Err(Error::Input);
        }
        let key_id = self.local_key_id.clone().unwrap();
        let key_id = key_id.as_slice();
        // convert len of generated key id to 16 bit
        let key_id_len = &[(key_id.len() >> 8) as u8, (key_id.len() & 0xff) as u8];

        // check len of message
        if byte_index + key_id_len.len() + key_id.len() > message.len() {
            return Err(Error::Input);
        }
        // write to message len of key id
        message[byte_index..byte_index + key_id_len.len()].copy_from_slice(key_id_len);
        byte_index += key_id_len.len();
        message[byte_index..byte_index + key_id.len()].copy_from_slice(key_id);
        byte_index += key_id.len();
        Ok(byte_index)
    }

    fn _write_static_key(
        &mut self,
        mut byte_index: usize,
        message: &mut [u8],
    ) -> Result<usize, Error> {
        if !self.s.is_on() {
            return Err(StateProblem::MissingKeyMaterial.into());
        } else if byte_index + self.s.pub_len() > message.len() {
            return Err(Error::Input);
        }

        if self.local_key_id.is_none() {
            return Err(Error::Input);
        }
        if self.is_initiator() {
            byte_index +=
                self.cipherstates.0.encrypt(self.s.pubkey(), &mut message[byte_index..])?;
        } else {
            byte_index +=
                self.cipherstates.1.encrypt(self.s.pubkey(), &mut message[byte_index..])?;
        }
        Ok(byte_index)
    }

    fn _read_sae_id<'a>(&mut self, ptr_main: &'a [u8]) -> Result<&'a [u8], Error> {
        let mut ptr = ptr_main;
        if ptr.len() < 2 {
            return Err(Error::Input);
        }
        let len_buf = &ptr[..2];
        ptr = &ptr[2..];
        let remote_sae_id_len = ((len_buf[0] as usize) << 8) + (len_buf[1] as usize);
        if ptr.len() < remote_sae_id_len {
            return Err(Error::Input);
        }
        let remote_sae_id = ptr[..remote_sae_id_len].to_vec();
        self.remote_sae_id = Some(remote_sae_id);
        ptr = &ptr[remote_sae_id_len..];
        Ok(ptr)
    }

    fn _read_key_id<'a>(&mut self, ptr_main: &'a [u8]) -> Result<&'a [u8], Error> {
        let mut ptr = ptr_main;
        if ptr.len() < 2 {
            return Err(Error::Input);
        }

        let len_buf = &ptr[..2];
        ptr = &ptr[2..];
        let remote_key_id_len = ((len_buf[0] as usize) << 8) + (len_buf[1] as usize);

        if ptr.len() < remote_key_id_len {
            return Err(Error::Input);
        }

        let remote_key_id = ptr[..remote_key_id_len].to_vec();
        ptr = &ptr[remote_key_id_len..];
        self.remote_key_id = Some(remote_key_id);
        Ok(ptr)
    }

    fn _read_static_key<'a>(&mut self, ptr_main: &'a [u8]) -> Result<&'a [u8], Error> {
        let mut ptr = ptr_main;
        let dh_len = self.dh_len();
        if ptr.len() < dh_len + TAGLEN {
            return Err(Error::Input);
        }
        let data = &ptr[..dh_len + TAGLEN];
        ptr = &ptr[dh_len + TAGLEN..];
        self.remote_enc_key = Some(data.to_vec());
        if !self.is_initiator() {
            self.cipherstates.0.decrypt(data, &mut self.rs[..dh_len])?;
        } else {
            self.cipherstates.1.decrypt(data, &mut self.rs[..dh_len])?;
        }
        self.rs.enable();

        Ok(ptr)
    }

    /// Construct a message from `payload` (and pending handshake tokens if in handshake state),
    /// and writes it to the `message` buffer.
    ///
    /// Returns the size of the written payload.
    ///
    /// # Errors
    ///
    /// Will result in `Error::Input` if the size of the output exceeds the max message
    /// length in the Noise Protocol (65535 bytes).
    pub fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error> {
        // let checkpoint = self.symmetricstate.checkpoint();
        match self._write_message(payload, message) {
            Ok(res) => {
                self.pattern_position += 1;
                self.my_turn = false;
                Ok(res)
            },
            Err(err) => {
                // self.symmetricstate.restore(checkpoint);
                Err(err)
            },
        }
    }

    fn _write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error> {
        if !self.my_turn {
            return Err(StateProblem::NotTurnToWrite.into());
        } else if self.pattern_position >= self.number_of_turn {
            return Err(StateProblem::HandshakeAlreadyFinished.into());
        }
        let mut byte_index = 0;
        // 0 <- SAE_ID
        //   -> enc_keys
        // 1 -> SAE_ID, KEY_ID
        //   <- dec_keys
        //   <- enc_keys
        // 2 <- KEY_ID, S
        //   -> dec_keys
        // 3 -> S
        match self.pattern_position {
            0 => {
                // SAE_ID
                byte_index = self._write_sae_id(byte_index, message)?;
            },
            1 => {
                // SAE_ID
                byte_index = self._write_sae_id(byte_index, message)?;
                // KEY_ID
                byte_index = self._write_key_id(byte_index, message)?;
            },
            2 => {
                // KEY_ID
                byte_index = self._write_key_id(byte_index, message)?;
            },
            3 => {
                //STATIC_KEY
                byte_index = self._write_static_key(byte_index, message)?;
            },
            4 => {
                // STATIC KEY
                byte_index = self._write_static_key(byte_index, message)?;
            },
            _ => {},
        }
        if self.pattern_position == 3 || self.pattern_position == 4 {
            if byte_index + payload.len() + TAGLEN > message.len() {
                return Err(Error::Input);
            }
            if self.is_initiator() {
                byte_index += self.cipherstates.0.encrypt(payload, &mut message[byte_index..])?;
            } else {
                byte_index += self.cipherstates.1.encrypt(payload, &mut message[byte_index..])?;
            }
        }
        if byte_index > MAXMSGLEN {
            return Err(Error::Input);
        }
        Ok(byte_index)
    }

    /// Reads a noise message from `input`
    ///
    /// Returns the size of the payload written to `payload`.
    ///
    /// # Errors
    ///
    /// Will result in `Error::Decrypt` if the contents couldn't be decrypted and/or the
    /// authentication tag didn't verify.
    ///
    /// Will result in `StateProblem::Exhausted` if the max nonce count overflows.
    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, Error> {
        // let checkpoint = self.symmetricstate.checkpoint();
        match self._read_message(message, payload) {
            Ok(res) => {
                self.pattern_position += 1;
                self.my_turn = true;
                Ok(res)
            },
            Err(err) => {
                // self.symmetricstate.restore(checkpoint);
                Err(err)
            },
        }
    }

    fn _read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, Error> {
        if message.len() > MAXMSGLEN {
            return Err(Error::Input);
        } else if self.my_turn {
            return Err(StateProblem::NotTurnToRead.into());
        } else if self.pattern_position >= self.number_of_turn {
            return Err(StateProblem::HandshakeAlreadyFinished.into());
        }
        let mut ptr = message;
        match self.pattern_position {
            0 => {
                ptr = self._read_sae_id(ptr)?;
            },
            1 => {
                ptr = self._read_sae_id(ptr)?;
                ptr = self._read_key_id(ptr)?;
            },
            2 => {
                ptr = self._read_key_id(ptr)?;
            },
            3 => {
                ptr = self._read_static_key(ptr)?;
            },
            4 => {
                ptr = self._read_static_key(ptr)?;
            },
            _ => {},
        }
        let payload_len = if self.pattern_position == 3 || self.pattern_position == 4 {
            if !self.is_initiator() {
                self.cipherstates.0.decrypt(ptr, payload)?
            } else {
                self.cipherstates.1.decrypt(ptr, payload)?
            }
        } else {
            0
        };
        Ok(payload_len)
    }

    /// Get the remote party's static public key, if available.
    ///
    /// Note: will return `None` if either the chosen Noise pattern
    /// doesn't necessitate a remote static key, *or* if the remote
    /// static key is not yet known (as can be the case in the `XX`
    /// pattern, for example).
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.rs.get().map(|rs| &rs[..self.dh_len()])
    }

    /// Get the handshake hash.
    ///
    /// Returns a slice of length `Hasher.hash_len()` (i.e. HASHLEN for the chosen Hash function).
    // pub fn get_handshake_hash(&self) -> &[u8] {
    // self.symmetricstate.handshake_hash()
    // }

    /// Check if this session was started with the "initiator" role.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Check if the handshake is finished and `into_transport_mode()` can now be called.
    pub fn is_handshake_finished(&self) -> bool {
        self.pattern_position == self.number_of_turn
    }

    /// Check whether it is our turn to send in the handshake state machine
    pub fn is_my_turn(&self) -> bool {
        self.my_turn
    }

    /// Perform the split calculation and return the resulting keys.
    ///
    /// This returns raw key material so it should be used with care. The "risky-raw-split"
    /// feature has to be enabled to use this function.
    #[cfg(feature = "risky-raw-split")]
    pub fn dangerously_get_raw_split(&mut self) -> ([u8; CIPHERKEYLEN], [u8; CIPHERKEYLEN]) {
        let mut output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.symmetricstate.split_raw(&mut output.0, &mut output.1);
        (output.0[..CIPHERKEYLEN].try_into().unwrap(), output.1[..CIPHERKEYLEN].try_into().unwrap())
    }

    /// Convert this `HandshakeState` into a `TransportState` with an internally stored nonce.
    pub fn into_transport_mode(self) -> Result<TransportState, Error> {
        self.try_into()
    }

    /// Convert this `HandshakeState` into a `StatelessTransportState` without an internally stored nonce.
    pub fn into_stateless_transport_mode(self) -> Result<StatelessTransportState, Error> {
        self.try_into()
    }
}

impl fmt::Debug for HandshakeState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("HandshakeState").finish()
    }
}
