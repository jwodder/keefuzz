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

#[derive(Clone, Debug, Eq, PartialEq)]
enum Arguments {
    Run { dbfile: PathBuf },
    ShowPreview(String),
    Help,
    Version,
}

impl Arguments {
    fn from_parser(mut parser: Parser) -> Result<Arguments, lexopt::Error> {
        let mut dbarg = None;
        while let Some(arg) = parser.next()? {
            match arg {
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
            Ok(Arguments::Run { dbfile })
        } else {
            Err("no database specified".into())
        }
    }

    fn run(self) -> Result<ExitCode, Error> {
        match self {
            Arguments::Run { dbfile } => run(dbfile)?,
            Arguments::ShowPreview(item) => show_preview(item).map_err(Error::Write)?,
            Arguments::Help => {
                write!(
                    io::stdout().lock(),
                    concat!(
                        "Usage: keefuzz [<options>] <database>\n",
                        "\n",
                        "TODO: Short description\n",
                        "\n",
                        "Visit <https://github.com/jwodder/keefuzz> for more information.\n",
                        "\n",
                        "Options:\n",
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
        if let Some(name) = self
            .title
            .as_ref()
            .or(self.url.as_ref())
            .or(self.username.as_ref())
        {
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

fn sanitize(s: &str) -> impl Iterator<Item = char> + '_ {
    // TODO: Properly expand tab characters
    s.chars()
        .filter(|&ch| ch != '\0')
        .map(|ch| if ch == '\t' { ' ' } else { ch })
}

fn run(dbfile: PathBuf) -> Result<(), Error> {
    let mut clipboard = arboard::Clipboard::new().map_err(Error::NewClipboard)?;
    let cfg = rpassword::ConfigBuilder::new()
        .password_feedback_mask('*')
        .build();
    let password =
        rpassword::prompt_password_with_config("DB Password: ", cfg).map_err(Error::GetPass)?;
    let mut fp = std::fs::File::open(dbfile).map_err(Error::OpenFile)?;
    let key = DatabaseKey::new().with_password(&password);
    let db = Database::open(&mut fp, key).map_err(Error::OpenDB)?;

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
        .arg("--read0")
        .arg("--delimiter=\\t")
        .arg("--with-nth={1}")
        .arg("--accept-nth={n}")
        .arg("--filepath-word")
        .arg("--preview")
        .arg(preview_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(Error::Spawn)?;
    let mut stdin = p.stdin.take().expect("p.stdin should start out non-None");
    for (id, item) in entries {
        ids.push(id);
        writeln!(&mut stdin, "{}", item.into_fzf_line()).map_err(Error::Write)?;
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
        clipboard.set_text(password).map_err(Error::SetClipboard)?;
        let _ = writeln!(io::stdout().lock(), "Password copied to clipboard");
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
    let mut anything = false;
    if !url.is_empty() {
        writeln!(&mut stdout, "URL: {url}")?;
        anything = true;
    }
    if !username.is_empty() {
        writeln!(&mut stdout, "Username: {url}")?;
        anything = true;
    }
    if !notes.is_empty() {
        writeln!(&mut stdout, "Notes:")?;
        for ln in notes.lines() {
            writeln!(&mut stdout, "    {ln}")?;
        }
        anything = true;
    }
    if !anything {
        writeln!(&mut stdout, "-- No Data --")?;
    }
    Ok(())
}

#[derive(Debug, Error)]
enum Error {
    #[error(transparent)]
    Usage(lexopt::Error),
    #[error("failed to obtain handle to system clipboard")]
    NewClipboard(arboard::Error),
    #[error(transparent)]
    GetPass(io::Error),
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
