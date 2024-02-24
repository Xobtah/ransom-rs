use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RendezVousError {
    #[error("FrankensteinError: {0}")]
    FrankensteinError(#[from] frankenstein::Error),
    #[error("IoError: {0}")]
    IoError(#[from] io::Error),
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),
}
