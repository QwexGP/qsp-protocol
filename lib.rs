use snow::params::NoiseParams;
use snow::{Builder, Keypair, TransportState};
use std::io::{Read, Write};

pub struct QspSession {
    state: TransportState,
}

impl QspSession {
    pub fn initiator(static_priv: &[u8; 32], remote_pub: &[u8; 32]) -> Result<(Self, Vec<u8>), snow::Error> {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2b".parse().unwrap();
        let builder = Builder::new(params);
        let mut handshake = builder
            .local_private_key(static_priv)
            .remote_public_key(remote_pub)
            .build_initiator()?;
        let mut buf = vec![0u8; 1024];
        let len = handshake.write_message(&[], &mut buf)?;
        let msg = buf[..len].to_vec();
        let state = handshake.into_transport_mode()?;
        Ok((QspSession { state }, msg))
    }

    pub fn responder(static_priv: &[u8; 32], mut incoming: impl Read) -> Result<(Self, Vec<u8>), snow::Error> {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2b".parse().unwrap();
        let builder = Builder::new(params);
        let mut handshake = builder.local_private_key(static_priv).build_responder()?;
        let mut buf = vec![0u8; 1024];
        incoming.read_exact(&mut buf)?;
        handshake.read_message(&buf, &mut [])?;
        let mut reply = vec![0u8; 1024];
        let len = handshake.write_message(&[], &mut reply)?;
        let msg = reply[..len].to_vec();
        let state = handshake.into_transport_mode()?;
        Ok((QspSession { state }, msg))
    }

    pub fn encrypt(&mut self, plaintext: &[u8], mut output: impl Write) -> Result<(), snow::Error> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = self.state.write_message(plaintext, &mut buf)?;
        output.write_all(&buf[..len])?;
        Ok(())
    }

    pub fn decrypt(&mut self, mut input: impl Read, output: &mut Vec<u8>) -> Result<(), snow::Error> {
        let mut buf = vec![0u8; 1024];
        let len = input.read(&mut buf)?;
        let mut decrypted = vec![0u8; len];
        let decrypted_len = self.state.read_message(&buf[..len], &mut decrypted)?;
        output.extend_from_slice(&decrypted[..decrypted_len]);
        Ok(())
    }
}

pub fn generate_keypair() -> Keypair {
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2b".parse().unwrap();
    Builder::new(params).generate_keypair().unwrap()
}
