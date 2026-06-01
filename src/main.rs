use keepass::{
    Database, DatabaseKey,
    db::{EntryId, GroupRef, fields::NOTES},
    error::DatabaseOpenError,
};
use lexopt::{Arg, Parser, ValueExt};
use std::io::{self, ErrorKind, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::process::{ExitCode, ExitStatus};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Arguments {
    Run(KeeFuzz),
    ShowPreview(String),
    Help,
    Version,
}

impl Arguments {
    fn from_parser(mut parser: Parser) -> Result<Arguments, lexopt::Error> {
        let mut dbarg = None;
        let mut print = false;
        let mut key_provider = KeyProvider::default();
        let mut fzf_options = Vec::new();
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("fzf-options") => match shell_words::split(&parser.value()?.string()?) {
                    Ok(args) => fzf_options = args,
                    Err(e) => {
                        return Err(format!("failed to split --fzf-options argument: {e}").into());
                    }
                },
                Arg::Short('F') | Arg::Long("password-file") => {
                    key_provider = KeyProvider::PasswordFile(PathBuf::from(parser.value()?));
                }
                Arg::Short('k') | Arg::Long("keyfile") => {
                    key_provider = KeyProvider::Keyfile(PathBuf::from(parser.value()?));
                }
                Arg::Long("no-key") => key_provider = KeyProvider::None,
                Arg::Short('p') | Arg::Long("print") => print = true,
                Arg::Long("show-preview") => {
                    return Ok(Arguments::ShowPreview(parser.value()?.string()?));
                }
                Arg::Short('h') | Arg::Long("help") => return Ok(Arguments::Help),
                Arg::Short('V') | Arg::Long("version") => return Ok(Arguments::Version),
                Arg::Value(arg) if dbarg.is_none() => {
                    dbarg = Some(PathBuf::from(arg));
                }
                _ => return Err(arg.unexpected()),
            }
        }
        if let Some(dbfile) = dbarg {
            Ok(Arguments::Run(KeeFuzz {
                dbfile,
                print,
                key_provider,
                fzf_options,
            }))
        } else {
            Err("no database specified".into())
        }
    }

    fn run(self) -> Result<ExitCode, Error> {
        match self {
            Arguments::Run(kf) => kf.run()?,
            Arguments::ShowPreview(item) => show_preview(item).map_err(Error::Write)?,
            Arguments::Help => {
                write!(
                    io::stdout().lock(),
                    concat!(
                        "Usage: keefuzz [<options>] <database>\n",
                        "\n",
                        "Look up passwords in a KeePass database with fzf\n",
                        "\n",
                        "Visit <https://github.com/jwodder/keefuzz> for more information.\n",
                        "\n",
                        "Options:\n",
                        "  --fzf-options ARGS\n",
                        "                    Add ARGS to the options passed to fzf\n",
                        "\n",
                        "  -F FILE, --password-file FILE\n",
                        "                    Read the database password from FILE\n",
                        "\n",
                        "  -k FILE, --keyfile FILE\n",
                        "                    Unlock the database using the given keyfile\n",
                        "\n",
                        "  --no-key          Assume the database is not protected with a password or\n",
                        "                    keyfile\n",
                        "\n",
                        "  -p, --print       Print out password instead of copying it to the clipboard\n",
                        "\n",
                        "  -h, --help        Display this help message and exit\n",
                        "  -V, --version     Show the program version and exit\n",
                    )
                )
                .map_err(Error::Write)?;
            }
            Arguments::Version => {
                writeln!(
                    io::stdout().lock(),
                    "{} {}",
                    env!("CARGO_PKG_NAME"),
                    env!("CARGO_PKG_VERSION")
                )
                .map_err(Error::Write)?;
            }
        }
        Ok(ExitCode::SUCCESS)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeeFuzz {
    dbfile: PathBuf,
    print: bool,
    key_provider: KeyProvider,
    fzf_options: Vec<String>,
}

impl KeeFuzz {
    fn run(self) -> Result<(), Error> {
        let clipboard = if !self.print {
            Some(arboard::Clipboard::new().map_err(Error::NewClipboard)?)
        } else {
            None
        };
        let db = {
            let mut fp = std::fs::File::open(self.dbfile).map_err(Error::OpenFile)?;
            let key = self.key_provider.into_key()?;
            Database::open(&mut fp, key).map_err(Error::OpenDB)?
        };
        let mut entries: Vec<(EntryId, Item)> = Vec::new();
        let root = db.root();
        traverse_entries(&mut entries, root, Vec::new());
        if entries.is_empty() {
            return Err(Error::EmptyDB);
        }
        entries.sort_unstable_by(|(_, a), (_, b)| a.cmp(b));
        let mut ids = Vec::with_capacity(entries.len());
        let this_bin = std::env::current_exe().map_err(Error::CurrentExe)?;
        let this_bin = this_bin.to_str().ok_or(Error::NonUtf8Exe)?;
        let preview_cmd = shell_words::join([this_bin, "--show-preview", "{}"]);
        let mut p = Command::new("fzf")
            .arg("--height=~40%")
            .arg("--reverse")
            .arg("--read0")
            .arg("--delimiter=\\t")
            .arg("--with-nth={1}")
            .arg("--accept-nth={n}")
            .arg("--filepath-word")
            .arg("--preview")
            .arg(preview_cmd)
            .args(self.fzf_options)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(Error::Spawn)?;
        let mut stdin = p.stdin.take().expect("p.stdin should start out non-None");
        for (id, item) in entries {
            ids.push(id);
            write!(&mut stdin, "{}", item.into_fzf_line()).map_err(Error::Write)?;
        }
        drop(stdin);
        let r = p.wait_with_output().map_err(Error::Wait)?;
        if r.status.code() == Some(0) {
            let stdout = String::from_utf8(r.stdout).map_err(Error::StdoutNotUtf8)?;
            let selection = match stdout.trim().parse::<usize>() {
                Ok(i) => i,
                Err(source) => {
                    return Err(Error::ParseStdout {
                        string: stdout,
                        source,
                    });
                }
            };
            let &entry_id = ids.get(selection).ok_or(Error::InvalidIndex(selection))?;
            let entry = db.entry(entry_id).ok_or(Error::EntryDisappeared)?;
            let password = entry.get_password().ok_or(Error::NoPassword)?;
            if let Some(mut cb) = clipboard {
                cb.set_text(password).map_err(Error::SetClipboard)?;
                let _ = writeln!(io::stdout().lock(), "Password copied to clipboard");
            } else {
                // --print mode
                let _ = writeln!(io::stdout().lock(), "{password}");
            }
            Ok(())
        } else if matches!(r.status.code(), Some(1 | 130)) {
            // No match/cancelled
            Ok(())
        } else if r.status.code().is_some() {
            Err(Error::Exit(r.status))
        } else {
            Err(Error::Signal(r.status))
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
enum KeyProvider {
    #[default]
    Prompt,
    PasswordFile(PathBuf),
    Keyfile(PathBuf),
    None,
}

impl KeyProvider {
    fn into_key(self) -> Result<DatabaseKey, Error> {
        match self {
            KeyProvider::Prompt => {
                let cfg = rpassword::ConfigBuilder::new()
                    .password_feedback_mask('*')
                    .build();
                let password = rpassword::prompt_password_with_config("DB Password: ", cfg)
                    .map_err(Error::GetPass)?;
                let password = Zeroizing::new(password);
                Ok(DatabaseKey::new().with_password(password.as_str()))
            }
            KeyProvider::PasswordFile(path) => {
                let mut s = std::fs::read_to_string(path).map_err(Error::ReadPasswordFile)?;
                if s.ends_with('\n') {
                    s.pop();
                    if s.ends_with('\r') {
                        s.pop();
                    }
                }
                let password = Zeroizing::new(s);
                Ok(DatabaseKey::new().with_password(password.as_str()))
            }
            KeyProvider::Keyfile(path) => {
                let mut fp = std::fs::File::open(path).map_err(Error::OpenKeyfile)?;
                DatabaseKey::new()
                    .with_keyfile(&mut fp)
                    .map_err(Error::ReadKeyfile)
            }
            KeyProvider::None => Ok(DatabaseKey::new()),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Item {
    group_path: Vec<String>,
    title: Option<String>,
    url: Option<String>,
    username: Option<String>,
    notes: Option<String>,
}

impl Item {
    // Output fields (tab-delimited):
    //  - group_path + (first defined of title, url, username, ???)
    //  - url
    //  - username
    //  - notes
    fn into_fzf_line(self) -> String {
        let mut s = String::new();
        for p in self.group_path {
            s.push('/');
            s.extend(sanitize(&p));
        }
        s.push('/');
        if let Some(name) = self.title.as_ref().filter(|s| !s.is_empty()) {
            s.extend(sanitize(name));
        } else if let Some(name) = self.url.as_ref().filter(|s| !s.is_empty()) {
            s.push('<');
            s.extend(sanitize(name));
            s.push('>');
        } else if let Some(name) = self.username.as_ref().filter(|s| !s.is_empty()) {
            s.extend(sanitize(name));
        } else {
            s.push_str("<no name>");
        }
        s.push('\t');
        s.extend(sanitize(self.url.as_deref().unwrap_or_default()));
        s.push('\t');
        s.extend(sanitize(self.username.as_deref().unwrap_or_default()));
        s.push('\t');
        s.extend(sanitize(self.notes.as_deref().unwrap_or_default()));
        s.push('\0');
        s
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error(transparent)]
    Usage(lexopt::Error),
    #[error("failed to obtain handle to system clipboard")]
    NewClipboard(arboard::Error),
    #[error("failed to read password from file: {0}")]
    ReadPasswordFile(io::Error),
    #[error(transparent)]
    GetPass(io::Error),
    #[error("failed to access keyfile: {0}")]
    OpenKeyfile(io::Error),
    #[error("failed to read keyfile: {0}")]
    ReadKeyfile(io::Error),
    #[error("failed to access database file: {0}")]
    OpenFile(io::Error),
    #[error("failed to load database: {0}")]
    OpenDB(DatabaseOpenError),
    #[error("no passwords in database")]
    EmptyDB,
    #[error("failed to determine path to our own executable: {0}")]
    CurrentExe(io::Error),
    #[error("failed to create --preview command: our own executable path is not UTF-8")]
    NonUtf8Exe,
    #[error("failed to spawn fzf process: {0}")]
    Spawn(io::Error),
    #[error("failed to write to fzf process: {0}")]
    Write(io::Error),
    #[error("error waiting for fzf process to terminate: {0}")]
    Wait(io::Error),
    #[error("fzf program exited with unexpected error code: {0}")]
    Exit(ExitStatus),
    #[error("fzf process killed by signal: {0}")]
    Signal(ExitStatus),
    #[error("fzf output was not UTF-8: {0}")]
    StdoutNotUtf8(std::string::FromUtf8Error),
    #[error("fzf output was not a valid integer: {string:?}: {source}")]
    ParseStdout {
        string: String,
        source: std::num::ParseIntError,
    },
    #[error("fzf returned out-of-bounds line index {0}")]
    InvalidIndex(usize),
    #[error("database entry no longer present")]
    EntryDisappeared,
    #[error("entry does not have a password")]
    NoPassword,
    #[error("failed to copy password to clipboard: {0}")]
    SetClipboard(arboard::Error),
}

impl Error {
    fn is_epipe_write(&self) -> bool {
        matches!(self, Error::GetPass(e) | Error::Write(e) if e.kind() == ErrorKind::BrokenPipe)
    }
}

fn main() -> ExitCode {
    match Arguments::from_parser(Parser::from_env())
        .map_err(Error::Usage)
        .and_then(Arguments::run)
    {
        Ok(code) => code,
        Err(e) if e.is_epipe_write() => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(io::stderr().lock(), "keefuzz: {e}");
            ExitCode::FAILURE
        }
    }
}

fn sanitize(s: &str) -> impl Iterator<Item = char> + '_ {
    // TODO: Properly expand tab characters
    s.chars()
        .filter(|&ch| ch != '\0')
        .map(|ch| if ch == '\t' { ' ' } else { ch })
}

fn traverse_entries(entries: &mut Vec<(EntryId, Item)>, group: GroupRef<'_>, path: Vec<String>) {
    for e in group.entries() {
        if e.get_password().is_some() {
            let item = Item {
                group_path: path.clone(),
                title: e.get_title().map(ToOwned::to_owned),
                url: e.get_url().map(ToOwned::to_owned),
                username: e.get_username().map(ToOwned::to_owned),
                notes: e.get(NOTES).map(ToOwned::to_owned),
            };
            entries.push((e.id(), item));
        }
    }
    for g in group.groups() {
        let mut subpath = path.clone();
        subpath.push(g.name.clone());
        traverse_entries(entries, g, subpath);
    }
}

fn show_preview(item: String) -> io::Result<()> {
    let mut bits = item.split('\t');
    let _path = bits.next();
    let url = bits.next().unwrap_or_default();
    let username = bits.next().unwrap_or_default();
    let notes = bits.next().unwrap_or_default();
    let mut stdout = io::stdout().lock();
    write_preview(&mut stdout, url, username, notes)
}

fn write_preview<W: Write>(
    mut writer: W,
    url: &str,
    username: &str,
    notes: &str,
) -> io::Result<()> {
    let mut anything = false;
    if !url.is_empty() {
        writeln!(&mut writer, "URL: {url}")?;
        anything = true;
    }
    if !username.is_empty() {
        writeln!(&mut writer, "Username: {username}")?;
        anything = true;
    }
    if !notes.is_empty() {
        writeln!(&mut writer, "Notes:")?;
        for ln in notes.lines() {
            writeln!(&mut writer, "    {ln}")?;
        }
        anything = true;
    }
    if !anything {
        writeln!(&mut writer, "-- No Data --")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    mod parse_args {
        use super::*;

        #[test]
        fn opts_after_database() {
            let parser = Parser::from_iter(["keefuzz", "passwords.kdbx", "--print"]);
            let args = Arguments::from_parser(parser).unwrap();
            assert_eq!(
                args,
                Arguments::Run(KeeFuzz {
                    dbfile: "passwords.kdbx".into(),
                    print: true,
                    key_provider: KeyProvider::default(),
                    fzf_options: Vec::new(),
                })
            );
        }

        #[test]
        fn keefuzz_option_to_fzf() {
            let parser = Parser::from_iter(["keefuzz", "--fzf-options", "-p", "passwords.kdbx"]);
            let args = Arguments::from_parser(parser).unwrap();
            assert_eq!(
                args,
                Arguments::Run(KeeFuzz {
                    dbfile: "passwords.kdbx".into(),
                    print: false,
                    key_provider: KeyProvider::default(),
                    fzf_options: vec!["-p".into()],
                })
            );
        }

        #[test]
        fn quoted_fzf_option() {
            let parser = Parser::from_iter([
                "keefuzz",
                "--fzf-options",
                "--preview-label 'Entry Details'",
                "passwords.kdbx",
            ]);
            let args = Arguments::from_parser(parser).unwrap();
            assert_eq!(
                args,
                Arguments::Run(KeeFuzz {
                    dbfile: "passwords.kdbx".into(),
                    print: false,
                    key_provider: KeyProvider::default(),
                    fzf_options: vec!["--preview-label".into(), "Entry Details".into()],
                })
            );
        }
    }

    mod fzf_lines {
        use super::*;

        #[test]
        fn uses_title_as_display_name() {
            let item = Item {
                group_path: vec!["Internet".into(), "Work".into()],
                title: Some("Example".into()),
                url: Some("https://example.com".into()),
                username: Some("alice".into()),
                notes: Some("login notes".into()),
            };

            assert_eq!(
                item.into_fzf_line(),
                "/Internet/Work/Example\thttps://example.com\talice\tlogin notes\0"
            );
        }

        #[test]
        fn falls_back_to_url_username_then_no_name() {
            let url_item = Item {
                group_path: Vec::new(),
                title: None,
                url: Some("https://example.com".into()),
                username: Some("alice".into()),
                notes: None,
            };
            let username_item = Item {
                group_path: Vec::new(),
                title: None,
                url: None,
                username: Some("alice".into()),
                notes: None,
            };
            let unnamed_item = Item {
                group_path: Vec::new(),
                title: None,
                url: None,
                username: None,
                notes: None,
            };

            assert_eq!(
                url_item.into_fzf_line(),
                "/<https://example.com>\thttps://example.com\talice\t\0"
            );
            assert_eq!(username_item.into_fzf_line(), "/alice\t\talice\t\0");
            assert_eq!(unnamed_item.into_fzf_line(), "/<no name>\t\t\t\0");
        }

        #[test]
        fn sanitizes_tabs_and_nuls() {
            let item = Item {
                group_path: vec!["Group\tOne".into()],
                title: Some("Ti\0tle".into()),
                url: Some("https://exa\tmple.com".into()),
                username: Some("ali\0ce".into()),
                notes: Some("line\t1\0".into()),
            };

            assert_eq!(
                item.into_fzf_line(),
                "/Group One/Title\thttps://exa mple.com\talice\tline 1\0"
            );
        }
    }

    mod preview {
        use super::*;

        #[test]
        fn writes_available_fields() {
            let mut output = Vec::new();

            write_preview(
                &mut output,
                "https://example.com",
                "alice",
                "line 1\nline 2",
            )
            .unwrap();

            assert_eq!(
                String::from_utf8(output).unwrap(),
                "URL: https://example.com\nUsername: alice\nNotes:\n    line 1\n    line 2\n"
            );
        }

        #[test]
        fn writes_no_data_message() {
            let mut output = Vec::new();

            write_preview(&mut output, "", "", "").unwrap();

            assert_eq!(String::from_utf8(output).unwrap(), "-- No Data --\n");
        }
    }
}
