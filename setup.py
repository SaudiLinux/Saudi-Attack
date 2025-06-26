#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import os

# قراءة محتوى ملف README.md
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# قراءة متطلبات التثبيت من ملف requirements.txt
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="saudi-attack",
    version="1.0.0",
    author="Saudi Linux",
    author_email="SaudiLinux7@gmail.com",
    description="أداة لإدارة سطح الهجوم وفحص الثغرات الأمنية",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SaudiLinux/SaudiAttack",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "saudi-attack=saudi_attack:main",
        ],
    },
    package_data={
        "": ["templates/*", "data/*"],
    },
)