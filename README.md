# Demeuk
[![Documentation Status](https://readthedocs.org/projects/demeuk/badge/?version=latest)](https://demeuk.readthedocs.io/en/latest/?badge=latest) [![Tests](https://github.com/NetherlandsForensicInstitute/demeuk/actions/workflows/test.yml/badge.svg)](https://github.com/NetherlandsForensicInstitute/demeuk/actions/workflows/test.yml)

Demeuk is a simple tool to clean up corpora (like dictionaries) or any dataset
containing plain text strings. Example use cases are: cleaning up language dictionaries,
password sets (like for example RockYou) or any file / stdin containing plain text strings.

In those corpora you'll find encoding mistakes that have been made, or you want to remove some parts
of a line. Instead of creating a huge bash oneliner you can use demeuk to do all your cleaning.

Example usages:
 - Cutting
 - Length checking
 - Encoding fixing

Demeuk is written in Python3, this means of course that it is slower than for example cut.
However, Demeuk is written multithreaded and thus can use all your cores. Besides this Demeuk
can easily be extended to match your needs.

This application is part of the CERBERUS project that has received
funding from the European Union's Internal Security Fund - Police under
grant agreement No. 82201

Please read the docs for more information.

## Quick start
Demeuk supports Python versions 3.12 and up.
The recommended way to install demeuk is to use [pipx](https://pipx.pypa.io/stable/).

```
pipx install demeuk --python /usr/bin/python3.14
```

Now you can invoke demeuk directly from the command-line from any directory:
```
demeuk --version
demeuk --help
demeuk -i inputfile.tmp -o outputfile.dict -l droppedfile.txt
demeuk -i inputfile -o outputfile -j 24 -l logfile.log
demeuk -i inputfile.tmp -o outputfile.dict -l droppedfile.txt --leak
demeuk -i inputfile -o outputfile -j 24 -l logfile.log --leak-full
demeuk -i inputdir/*.txt -o outputfile.dict -l logfile.log
demeuk -o outputfile.dict -l logfile.log
```

Alternatively you can install demeuk in a venv as usual, in which case the `demeuk` command becomes available while the venv is active.
```
pip install demeuk
```

Demeuk follows conventions of other text-processing shell tools: it can take input from stdin, and demeuk outputs its results to stdout, with logs being written to stderr.
```
    cat wordlist | demeuk --leak-full --debug > list.out 2> list.log
```

## Development
To make changes to demeuk, you need to run it from the source Python files.
```
git clone https://github.com/NetherlandsForensicInstitute/demeuk.git
cd demeuk
pipx install ./ --python /usr/bin/python3.14
```
Now you can run demeuk as in the examples. Note that the shortcut `demeuk` only updates after you
run `pipx upgrade demeuk`.

You can install demeuk through PDM with `pdm install -p ./`, this circumvents this issue although you have to
run demeuk with `pdm run demeuk`.

Check the version:
```
demeuk -version
```

Usage:
```
demeuk --help
```


## Docs
The docs are available at: <http://demeuk.rtfd.io/>

To build the documentation locally with PDM:

```
pdm install -G docs
pdm run make -C docs html
```

The generated site is in `docs/_build/html/`. On Windows, run
`pdm run docs\make.bat html` instead of `make`.
