use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};

fn main() -> io::Result<()> {

    // Specify the types of clippy linting to ignore; keep security related ones around
    // just in case.
    let directives = "#![allow(clippy::style)]\n#![allow(clippy::too_many_arguments)]";

    let path = "src/lib.rs";
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Check if the directives were already inserted.
    if !contents.contains(directives) { // The lib file isn't very long.
        let mut new_contents = format!("{}\n", directives).to_string();
        new_contents.push_str(&contents);

        // Set the file seek pointer to the top of the file so we add the directives
        // to the top of the file.
        file.seek(SeekFrom::Start(0))?;
        file.write_all(new_contents.as_bytes())?;
    }

    // Ensure that we rerun the lib.rs was altered by the client autogeneration.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");

    // Return.
    Ok(())
}
