#!/usr/bin/env python
from setuptools import setup

import io
import re
with io.open('roku_dev_cli/version.py', 'rt', encoding='utf8') as f:
    version = re.search(r'__version__ = \'(.*?)\'', f.read()).group(1)

setup(name='roku-dev-cli',
      version=version,
      description='Roku Command-Line Tool',
      author='Josh Stratton',
      author_email='josh.stratton@hulu.com',
      url='https://github.com/hulu/roku-dev-cli',
      packages=['roku_dev_cli'],
      include_package_data=True,
      entry_points={
        "console_scripts": ["roku=roku_dev_cli.roku_dev_cli:main"],
      },
      install_requires=[
          'beautifulsoup4',
          'graphviz',
          'ipaddress', # backport library, Python 2/3 compatible
          'requests'
      ]
     )
