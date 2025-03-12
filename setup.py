import codecs

from setuptools import setup

from bin.demeuk import VERSION

dependencies = [
    "docopt",
    "chardet",
    "nltk",
    "ftfy",
    "unidecode",
    "tqdm",
]

with open("README.md", "r", encoding="utf-8") as r:
    long_description = r.read()

setup(
    name="demeuk",
    version=VERSION,
    author="Netherlands Forensic Institute",
    author_email=codecs.encode("ubyzrfay@hfref.abercyl.tvguho.pbz", "rot-13"),  # type: ignore
    description="CLI tool to remove invalid chars from a corpus.",
    install_requires=dependencies,
    scripts=["bin/demeuk.py"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/NetherlandsForensicInstitute/demeuk",
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
