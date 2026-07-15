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

Examples:
```
    demeuk -i inputfile.tmp -o outputfile.dict -l demeuk.log
    demeuk -i inputfile -o outputfile -j 24 -l demeuk.log
    demeuk -i inputfile.tmp -o outputfile.dict -l demeuk.log --leak
    demeuk -i inputfile -o outputfile -j all -l demeuk.log --leak-full
    demeuk -i inputdir/*.txt -o outputfile.dict -l demeuk.log
```
Demeuk also works with pipes:
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

## Docs
The docs are available at: <http://demeuk.rtfd.io/>
