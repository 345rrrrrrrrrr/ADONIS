#!/usr/bin/env python3
# ADONIS - Setup script for distribution

import os
from setuptools import setup, find_packages

# Read version from package
VERSION = '0.1.0'
with open('src/version.py', 'w') as f:
    f.write(f'VERSION = "{VERSION}"\n')

# Read description from README.md
here = os.path.abspath(os.path.dirname(__file__))
try:
    with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "ADONIS - AI-powered Debugging and Offensive Network Integrated Suite"

# Read requirements
with open('requirements.txt') as f:
    requirements = f.read().splitlines()
    # Remove comments and empty lines
    requirements = [line for line in requirements if line and not line.startswith('#')]

setup(
    name="adonis",
    version=VERSION,
    description="AI-powered Debugging and Offensive Network Integrated Suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="ADONIS Team",
    author_email="info@adonistoolkit.org",
    license="MIT",
    url="https://github.com/adonistoolkit/adonis",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "adonis=main:main",
        ],
    },
    install_requires=requirements,
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Debuggers",
    ],
    include_package_data=True,
    zip_safe=False,
)