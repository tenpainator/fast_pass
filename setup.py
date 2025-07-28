#!/usr/bin/env python3
"""
FastPass Setup Configuration
Enables pip installation: pip install fastpass
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text() if (this_directory / "README.md").exists() else "FastPass - Universal File Encryption/Decryption Tool"

setup(
    name="fastpass",
    version="1.0.0",
    author="FastPass Development Team",
    author_email="fastpass@example.com",
    description="Universal file encryption and decryption tool for Office documents and PDFs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fastpass/fastpass",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: Office/Business",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "msoffcrypto-tool>=5.0.0",
        "PyPDF2>=3.0.0",
        "filetype>=1.2.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "fastpass=fastpass.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)