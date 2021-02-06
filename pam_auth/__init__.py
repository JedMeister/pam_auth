"""PAM authentication wrapper that supports root login.

pam_auth_py provides both a function and a class for user authentication via
the pam 'login' service. It supports root login via securetty. securetty can
be disabled for non root users if desired.

Note; Written on Debian for Debian, so may have some Debian idiosyncrasies...
"""

import subprocess
from pathlib import Path
import sys
import os

# tested with pip's 'python-pam' package, but should also work with Debian
# 'python3-pampy'.
import pam


def auth(username: str, password: str, secure_tty: bool = True) -> bool:
    """PAM authentication function."""
    auth_user = Auth(username, password, secure_tty=secure_tty)
    auth_user.authenticate()
    return auth_user.auth


class AuthError(Exception):
    """Error."""

    pass


class Auth:
    """PAM authentication class.

    When running as root, it supports login via any existing user, even root.
    Unlike default PAM it can check for access via secure tty for all users
    (not just root).
    """

    AuthError = AuthError

    def __init__(self, username: str, password: str, secure_tty: bool = True):
        """Initialise things as a good init should.

        Note: Authtentication does not happen automatically. A call to the
        authenticate() method is required.
        """
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
    def is_tty_secure() -> bool:
        """Manually check tty."""
        tty = subprocess.run(['tty'], capture_output=True, text=True).stdout
        if tty.startswith('/dev/'):
            tty = tty[5:]
        with open('/etc/securetty', 'r') as fob:
            if tty in fob:
                return True
        return False

    def authenticate(self, secure_tty: bool = True) -> None:
        """Authenticate user."""
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
        """Cleanup method."""
        try:
            self._login_tmp.unlink()
        except (FileNotFoundError, PermissionError):
            pass

    def __del__(self):
        """Magic method to ensure that temp file is cleaned up."""
        self.close()
