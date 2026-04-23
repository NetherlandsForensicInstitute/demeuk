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
Demeuk support Python versions 3.10 and up.
The recommended way to install demeuk is to use [PDM](https://pdm-project.org/en/latest/).

```
# Initialize an empty project
pdm -n --no-git --python 3.14
# Install demeuk
pdm add demeuk
```

Now you can invoke demeuk using `pdm run demeuk`

Examples:
```
    # From inside the install directory
    pdm run demeuk -i inputfile.tmp -o outputfile.dict -l droppedfile.txt
    pdm run demeuk -i inputfile -o outputfile -j 24 -l logfile.log
    pdm run demeuk -i inputfile.tmp -o outputfile.dict -l droppedfile.txt --leak
    # From outside the install directory
    pdm run -p /path/to/demeuk demeuk -i inputfile -o outputfile -j 24 -l logfile.log --leak-full
    pdm run -p /path/to/demeuk demeuk -i inputdir/*.txt -o outputfile.dict -l logfile.log
    pdm run -p /path/to/demeuk demeuk -o outputfile.dict -l logfile.log
```

## Running from source
To make changes to demeuk, you need to run it from the source Python files.
```
git clone https://github.com/NetherlandsForensicInstitute/demeuk.git
cd demeuk
# Choose a Python interpreter (optional)
pdm use
# Install dependencies
pdm install
# Run the included test suite
pdm test
```
Now you can run demeuk as in the examples.

## Docs
The docs are available at: <http://demeuk.rtfd.io/>
