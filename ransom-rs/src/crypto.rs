use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead, OsRng},
    KeyInit, XChaCha20Poly1305,
};
use log::{debug, info};
use rand::RngCore;

pub const ENCRYPTED_FILE_EXTENSION: &str = "hzt";
pub const KEY_SIZE: usize = 32;
const BUFFER_BASE_LEN: usize = 500;
const STREAM_THRESHOLD: usize = 1024 * 1024 * 500; // 500 MB

pub struct Key([u8; KEY_SIZE]);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl std::str::FromStr for Key {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key"))
    }
}

impl std::convert::TryFrom<&[u8]> for Key {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != KEY_SIZE {
            return Err(anyhow!("Key must be {} bytes long", KEY_SIZE));
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(value);
        Ok(Self(key))
    }
}

impl std::convert::TryFrom<Vec<u8>> for Key {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl std::ops::Deref for Key {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Key {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let key = Self(key);
        info!("Generated key: {}", key);
        key
    }

    pub fn get(key: String) -> Result<Self, anyhow::Error> {
        if key.len() != KEY_SIZE * 2 {
            return Err(anyhow::anyhow!("Key must be {} characters long", KEY_SIZE));
        }
        hex::decode(key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key"))
    }

    pub fn get_or_new(key: Option<String>) -> Result<Self, anyhow::Error> {
        if let Some(key) = key {
            Self::get(key)
        } else {
            Ok(Self::new())
        }
    }
}

pub struct Crypto;

impl Crypto {
    pub fn encrypt(
        key: &Key,
        source_file_path: &Path,
        dist_file_path: &Path,
    ) -> Result<(), anyhow::Error> {
        debug!("Encrypting {source_file_path:?}");
        if fs::metadata(source_file_path)?.len() < STREAM_THRESHOLD as u64 {
            debug!("Encrypting {source_file_path:?} as block");
            fs::write(
                dist_file_path,
                Self::block_encrypt(key, fs::read(source_file_path)?.as_ref())?,
            )?;
        } else {
            debug!("Encrypting {source_file_path:?} as stream");
            Self::stream_encrypt(key, source_file_path, dist_file_path)?;
        }
        Ok(())
    }

    pub fn decrypt(
        key: &Key,
        encrypted_file_path: &Path,
        dist: &Path,
    ) -> Result<(), anyhow::Error> {
        debug!("Decrypting {encrypted_file_path:?}");
        if fs::metadata(encrypted_file_path)?.len() < STREAM_THRESHOLD as u64 {
            debug!("Decrypting {encrypted_file_path:?} as block");
            fs::write(
                dist,
                Self::block_decrypt(key, fs::read(encrypted_file_path)?.as_ref())?,
            )?;
        } else {
            debug!("Decrypting {encrypted_file_path:?} as stream");
            Self::stream_decrypt(key, encrypted_file_path, dist)?;
        }
        Ok(())
    }

    fn block_encrypt(key: &Key, data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        debug!("Block encrypting {} bytes", data.len());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut encrypted_data = XChaCha20Poly1305::new(key.as_ref().into())
            .encrypt(nonce.as_ref().into(), data)
            .map_err(|err| anyhow!("Encrypting small file: {}", err))?;
        encrypted_data.splice(..0, nonce.iter().cloned());
        Ok(encrypted_data)
    }

    fn block_decrypt(key: &Key, encrypted_data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        debug!("Block decrypting {} bytes", encrypted_data.len());
        let nonce = &encrypted_data[..24];
        XChaCha20Poly1305::new(key.as_ref().into())
            .decrypt(nonce.as_ref().into(), &encrypted_data[24..])
            .map_err(|err| anyhow!("Decrypting small file: {}", err))
    }

    fn stream_encrypt(
        key: &Key,
        source_file_path: &Path,
        dist_file_path: &Path,
    ) -> Result<(), anyhow::Error> {
        let mut nonce = [0u8; 19];
        OsRng.fill_bytes(&mut nonce);
        debug!(
            "Stream encrypting {source_file_path:?} with nonce {}",
            hex::encode(nonce)
        );
        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
        const BUFFER_LEN: usize = BUFFER_BASE_LEN;
        let mut buffer = [0u8; BUFFER_LEN];

        let mut source_file = fs::File::open(source_file_path)?;
        let mut dist_file = fs::File::create(dist_file_path)?;
        dist_file.write(&nonce)?; // TODO Write buffer length and iteration count
        let mut written = 0;
        loop {
            let read_count = source_file.read(&mut buffer)?;

            if read_count == BUFFER_LEN {
                let ciphertext = stream_encryptor
                    .encrypt_next(buffer.as_slice())
                    .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
                dist_file.write(&ciphertext)?;
            } else {
                let ciphertext = stream_encryptor
                    .encrypt_last(&buffer[..read_count])
                    .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
                dist_file.write(&ciphertext)?;
                break;
            }
            written += read_count;
            if written % STREAM_THRESHOLD == 0 {
                debug!("Stream encrypted {} bytes", written);
            }
        }
        debug!("Stream encrypted {source_file_path:?}");
        Ok(())
    }

    fn stream_decrypt(
        key: &Key,
        encrypted_file_path: &Path,
        dist: &Path,
    ) -> Result<(), anyhow::Error> {
        let mut encrypted_file = fs::File::open(encrypted_file_path)?;
        let mut dist_file = fs::File::create(dist)?;
        let mut nonce = [0u8; 19];
        encrypted_file.read(&mut nonce)?;
        debug!(
            "Stream decrypting {encrypted_file_path:?} with nonce {}",
            hex::encode(nonce)
        );

        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());
        const BUFFER_LEN: usize = BUFFER_BASE_LEN + 16;
        let mut buffer = [0u8; BUFFER_LEN];

        let mut written = 0;
        loop {
            let read_count = encrypted_file.read(&mut buffer)?;

            if read_count == BUFFER_LEN {
                let plaintext = stream_decryptor
                    .decrypt_next(buffer.as_slice())
                    .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
                dist_file.write(&plaintext)?;
            } else if read_count == 0 {
                break;
            } else {
                let plaintext = stream_decryptor
                    .decrypt_last(&buffer[..read_count])
                    .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
                dist_file.write(&plaintext)?;
                break;
            }
            written += read_count;
            if written % STREAM_THRESHOLD == 0 {
                debug!("Stream decrypted {} bytes", written);
            }
        }
        debug!("Stream decrypted {encrypted_file_path:?}");
        Ok(())
    }
}
