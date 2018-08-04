"""Tests for the passlib authenticator."""

from argparse import ArgumentParser
from contextlib import contextmanager
from os import environ, path, remove
from shutil import copy2, rmtree
from tempfile import mkdtemp

import pytest
from passlib.apache import HtpasswdFile

from pypiserver_passlib.auth import PasslibAuthenticator


@pytest.fixture()
def htpasswd_file():
    """Create a new htpasswd file and return the path and instance."""
    tmpdir = mkdtemp()
    passpath = path.join(tmpdir, 'htpasswd.pass')
    HtpasswdFile(passpath, new=True).save()
    yield passpath
    rmtree(tmpdir)


@contextmanager
def logins(passfile_path, *logins):
    """Add (username, password) pairs to htpasswd file."""
    passbak_path = '{}.bak'.format(passfile_path)
    copy2(passfile_path, passbak_path)
    passfile = HtpasswdFile(passfile_path)
    for uname, password in logins:
        passfile.set_password(uname, password)
    passfile.save()
    yield
    remove(passfile_path)
    copy2(passbak_path, passfile_path)


@contextmanager
def update_env(**kwargs):
    """Update environment and then set it back."""
    start = environ.copy()
    environ.update(**kwargs)
    yield
    environ.clear()
    environ.update(**start)


class GenericNamespace(object):
    """A simple namespace object."""

    def __init__(self, **kwargs):
        for name, value in kwargs.items():
            setattr(self, name, value)


def req(login, pw):
    """Create a mock request with the proper auth property."""
    return GenericNamespace(auth=(login, pw))


def test_authenticate_htpasswd(htpasswd_file):
    """Test authenticating via an Htpasswd file."""
    conf = GenericNamespace(password_file=htpasswd_file)
    with logins(htpasswd_file, ('foo', 'foobar')):
        assert PasslibAuthenticator(conf).authenticate(req('foo', 'foobar'))


def test_authenticate_htpasswd_fail(htpasswd_file):
    """Test failing to authenticate via an Htpasswd file."""
    conf = GenericNamespace(password_file=htpasswd_file)
    with logins(htpasswd_file, ('foo', 'foobar')):
        assert not PasslibAuthenticator(conf).authenticate(req('foo', 'asb'))


def test_authenticate_none():
    """Test overriding auth."""
    conf = GenericNamespace(password_file='.')
    assert PasslibAuthenticator(conf).authenticate(req('a', 'b'))


class TestConfig(object):
    """Test config updates."""

    def test_updating_parser(self):
        """Test the updating of the argument parser."""
        parser = ArgumentParser()
        PasslibAuthenticator.update_parser(parser)
        assert parser.parse_args().password_file is None

    def test_pull_from_env(self):
        """Test pulling from the environment."""
        with update_env(PYPISERVER_PASSWORD_FILE='foo'):
            parser = ArgumentParser()
            PasslibAuthenticator.update_parser(parser)
            assert parser.parse_args().password_file == 'foo'

    def test_direct_specification(self):
        """Test specifying the password file directly."""
        parser = ArgumentParser()
        PasslibAuthenticator.update_parser(parser)
        assert parser.parse_args(
            ['--password-file', 'bar']
        ).password_file == 'bar'
