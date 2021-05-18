#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import setuptools

version = "0.1.3"

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aiobroadlink",
    packages=["aiobroadlink"],
    version=version,
    author="François Wautier.",
    author_email="francois@wautier.eu",
    description="Pure Python library to control/provision Broadlink devices",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/frawau/aiobroadlink",
    platforms=["unix", "linux", "osx"],
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: Software Development :: Libraries",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    keywords=["Broadlink", "IoT", "WiFi", "Home Automation", "asyncio",],
    install_requires=["cryptography >= 2.8"],
    entry_points={"console_scripts": ["aiobroadlink=aiobroadlink.__main__:main"],},
    zip_safe=False,
)
