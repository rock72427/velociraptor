#!/usr/bin/env python3
"""
Setup script for Velociraptor
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="velociraptor",
    version="1.0.0",
    author="Security Researcher",
    author_email="researcher@example.com",
    description="Automated Penetration Testing Reconnaissance Tool",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/velociraptor",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.7",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "velociraptor=velociraptor:main",
        ],
    },
    include_package_data=True,
    package_data={
        "velociraptor": ["*.txt", "*.md", "*.json"],
    },
    keywords="security, penetration-testing, reconnaissance, automation, kali-linux",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/velociraptor/issues",
        "Source": "https://github.com/yourusername/velociraptor",
        "Documentation": "https://github.com/yourusername/velociraptor/wiki",
    },
) 