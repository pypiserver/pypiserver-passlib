#!/usr/bin/env python
"""Build wheels/dists."""

import sys
from argparse import ArgumentParser
from os import path
from subprocess import Popen


THIS_DIR = path.abspath(path.dirname(__file__))
ROOT_DIR = path.abspath(path.join(THIS_DIR, '..'))
SETUP_PATH = path.join(ROOT_DIR, 'setup.py')


def parse_args():
    """Parse arguments."""
    parser = ArgumentParser()
    parser.add_argument(
        '--tags',
        nargs='+',
        default=(),
        help='Provide release tags (like "rc1", ".dev2", or "post1")'
    )
    return parser.parse_args()


def _build(*tags):
    """Yield the build command."""
    for part in (sys.executable, SETUP_PATH, 'bdist_wheel', 'sdist'):
        yield part
    # import ipdb; ipdb.set_trace()
    if tags:
        yield 'egg_info'
        for tag in tags:
            yield '--tag-build'
            yield tag


def build(*tags):
    """Build the artifacts."""
    Popen(_build(*tags)).communicate()


if __name__ == '__main__':
    args = parse_args()
    build(*args.tags)
