[![Project Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip)
[![CI Status](https://github.com/jwodder/keefuzz/actions/workflows/test.yml/badge.svg)](https://github.com/jwodder/keefuzz/actions/workflows/test.yml)
[![Minimum Supported Rust Version](https://img.shields.io/badge/MSRV-1.88-orange)](https://www.rust-lang.org)
[![MIT License](https://img.shields.io/github/license/jwodder/keefuzz.svg)](https://opensource.org/licenses/MIT)

[GitHub](https://github.com/jwodder/keefuzz) | [Issues](https://github.com/jwodder/keefuzz/issues)

`keefuzz` is a simple command-line program for interactively selecting an entry
from a KeePass password database with [`fzf`][] and then copying the entry's
password to the clipboard.

[`fzf`]: https://github.com/junegunn/fzf

Installation
============

In order to install `keefuzz`, you first need to have [Rust and Cargo
installed](https://www.rust-lang.org/tools/install).  You can then build the
latest version of `keefuzz` and install it in `~/.cargo/bin` by running:

    cargo install --git https://github.com/jwodder/keefuzz


External Dependencies
---------------------

[`fzf`][] must be installed separately in order for `keyfuzz` to function.

Usage
=====

    keefuzz [<options>] <database>

`keefuzz` takes one mandatory argument: the path to a KeePass database file.
On startup, the user is prompted for the password for the database itself.
Entries are then read from the database, and their information is passed to
[`fzf`][], which handles the selection user interface.  Entries that don't
actually contain passwords are omitted from the selection list.

Each line in the `fzf` selection list consists of the slash-separated group
path to an entry, ending with the entry's title.  If an entry lacks a title,
the URL is used instead (enclosed in angle brackets), falling back to the
username and then the string "`<no name>`".  The username, URL, and notes (if
any) for the currently-selected line can be seen in a "preview" window on the
right of the display.

Once an entry is accepted, its password is copied to the system clipboard (or
printed to stdout if the `--print` option was given).  If the user exits `fzf`
without selecting anything (by pressing <kbd>Ctrl</kbd>-<kbd>C</kbd> or
<kbd>Esc</kbd>), nothing will be copied to the clipboard or printed to stdout.

Options
-------

- `-p`, `--print` — Print the password for the chosen entry to stdout instead
  of copying it to the clipboard

- `-h`, `--help` — Show command-line usage

- `-V`, `--version` — Show current program version


NO WARRANTY OR GUARANTEE OF SECURITY
====================================

Although `keefuzz`'s license already states this, given that the project deals
with sensitive data, it bears repeating:

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

In particular, the developers of `keefuzz` make no guarantees about it being a
secure way to access a KeePass database.  As an example of the level of
security this project exhibits, while `keefuzz` and `fzf` are running, the
passwords in the database can be read directly from `keefuzz`'s memory.
Whether you consider this acceptable security-wise depends on your threat
model.
