#!/usr/bin/env python3
"""
LogMind Setup Script
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="logmind",
    version="1.0.0",
    author="gitstq",
    author_email="",
    description="🧠 LogMind - Lightweight Terminal Log Intelligent Analysis Engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gitstq/LogMind",
    py_modules=["logmind"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "logmind=logmind:main",
        ],
    },
    keywords="log analysis monitoring cli terminal devops debugging troubleshooting",
    project_urls={
        "Bug Reports": "https://github.com/gitstq/LogMind/issues",
        "Source": "https://github.com/gitstq/LogMind",
    },
)
