import subprocess
from pathlib import Path
import sys
import os

import pam


def auth(username, password, secure_tty=True):
    auth_user = Auth(username, password, secure_tty=secure_tty)
    auth_user.authenticate()
    return auth_user.auth


class AuthError(Exception):
    pass


class Auth:
    """PAM authentication class. When running as root, it supports login via
       any existing user, even root. Unlike default PAM it can check for access
       via secure tty for all users (not just root).
    """

    AuthError = AuthError

    def __init__(self, username, password, secure_tty=True):

        _login = Path('/etc/pam.d/login')
        self.pam_service = _login.name
        self._login_tmp = Path('/etc/pam.d/login.tmp')
        if os.getuid() == 0:
            with _login.open('r') as fob1, self._login_tmp.open('w') as fob2:
                for line in fob1:
                    if 'pam_securetty.so' in line:
                        line = f'#{line}'
                    fob2.write(line)
            self.pam_service = self._login_tmp.name

        self.username = username
        self.password = password

        self.auth = False
        self.reason = 'auth not yet attempted; use authenticate()'
        self.code = 1

    @staticmethod
    def is_tty_secure():
        """manually check tty"""
        tty = subprocess.run(['tty'], capture_output=True, text=True).stdout
        if tty.startswith('/dev/'):
            tty = tty[5:]
        with open('/etc/securetty', 'r') as fob:
            if tty in fob:
                return True
        return False

    def authenticate(self, secure_tty=True):
        """authenticate user"""
        if self.username == 'root':
            if not secure_tty:
                raise self.AuthError('root always requires secure tty.')

        if secure_tty and not self.is_tty_secure():
            raise self.AuthError('insecure tty')

        p = pam.pam()
        self.auth = p.authenticate(self.username, self.password,
                                   service=self.pam_service)
        self.reason = p.reason
        self.code = p.code

    def close(self):
        try:
            self._login_tmp.unlink()
        except (FileNotFoundError, PermissionError):
            pass

    def __del__(self):
        self.close()
