#!/usr/bin/python

import setuptools

with open("./dnstap_receiver/__init__.py", "r") as fh:
    for line in fh.read().splitlines():
        if line.startswith('__version__'):
            PKG_VERSION = line.split('"')[1]
            
with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()
    
KEYWORDS = ('dnstap receiver client json yaml text')

setuptools.setup(
    name="dnstap_receiver",
    version=PKG_VERSION,
    author="Denis MACHARD",
    author_email="d.machard@gmail.com",
    description="Python Dnstap receiver",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/dmachard/dnstap_receiver",
    packages=['dnstap_receiver'],
    include_package_data=True,
    platforms='any',
    keywords=KEYWORDS,
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries",
    ],
    entry_points={'console_scripts': ['dnstap_receiver = dnstap_receiver.receiver:start_receiver']},
    install_requires=[
        "dnspython",
        "protobuf",
        "pyyaml",
        "aiohttp"
    ]
)
