# Changelog

## 5.0.0 - 2026-11-18
Welcome to the release of demeuk 5.0.0! This version reworks most of the internals of demeuk, moving to a modular pipeline structure from a static fixed-order pipeline. Most of the changes are to the inner workings of the program, so demeuk works just as it did before. Some command-line flags are added and some optimizations introduced. Furthermore many small bugs are now fixed.
### Major changes
- demeuk now uses simple modules for every check/modification/operation, and builds a pipeline from a given command, where the modules are placed in the order that they appear on in the command-line. This allows more control over how different modules interact, think for example about the `--check-min-length` and `--add-split` modules. The output differs depending on the order in which these modules are run on a given input list. For a more detailed explanation, see the docs (Design section).
- All modules now subclass `Module`, which provides an interface that is used by the pipeline. This makes implementing new modules easier and less prone to errors.
- Automatically discover modules in the `modules/` directory.
- New modules:
  - `--uppercase` which replaces a line with its uppercase variant
  - `--add-upper` which adds the capitalized line
- `--profile` option which runs demeuk single-threaded without any chunking. This can be used to profile the runtime of the different modules used.
- Enable progress bar by default. Disable with `--no-progress`, or enable it with ``--progress`` if you redirect stderr.
- Update the build system so that demeuk is a python package, built with `pdm`. This makes it so you can run `demeuk` directly as a command after installing with `pipx`, instead of having to run the `demeuk.py` script.
- Move from `requirements.txt` and `setup.py` to a more modern `pyproject.toml`.
- Updated README and docs, and added a guide on how to implement new modules.

### Minor changes
- Parse command-line with `argparse` instead of `docopt`.
  - This also allows arguments with a value to be passed with an equals sign, for example `--check-max-length=16`.
- Drop support for Python 3.9, and support up to Python 3.15
- Reordered modules into five major categories: Check, Add, Remove, Modify and Macro.
- Re-enable `--mojibake` module when running `--leak-full`
- Fix incorrect hash regexes for `crypt` and `bcrypt`.
- Update some help strings to be more clear (`--help`)
- Automatic linting and formatting with `ruff`.
- Use `pathlib` where possible, instead of `os.path`.
- Update NLTK dependency to 3.10.4
- Optimized `--mojibake`, `--check-email`, `--check-mac-address`, `--check-uuid` and `--check-hash` speed by pre-filtering based on character class (Mojibakes must be non-ascii), character appearance (email must contain '@') or length (UUID is always 36 long)
- If no arguments are passed to `demeuk`, show usage and quit instead of waiting for input from `stdin`.
