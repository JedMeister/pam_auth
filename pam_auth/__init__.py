"""PAM authentication wrapper that supports root login.

pam_auth_py provides both a function and a class for user authentication via
the PAM 'login' service.

Despite the different approach to user integration, much of the heavy lifting
is done by the python-pam module. Beyond python-pam's functionality,
pam_auth_py provides some additional features/functionality:

    - Allows root to authenticate via the PAM 'login' service (not possible
      by default in python-pam module). This means that when running as root,
      it supports authentication for any existing user, even root itself.
    - The ability to check the current tty agsinst the system designated
      secure ttys for all users, not just root. On by default.

Note: Written on Debian for Debian, so may have some Debian idiosyncrasies...
"""

import subprocess
from pathlib import Path
import os

# tested with pip's 'python-pam' package, but should also work with Debian
# 'python3-pampy'.
import pam  # type: ignore


def auth(username: str, password: str, secure_tty: bool = True) -> bool:
    """PAM authentication function."""
    auth_user = Auth(username, password)
    auth_user.authenticate(secure_tty=secure_tty)
    return auth_user.auth


class AuthError(Exception):
    """Error."""


class Auth:
    """PAM authentication class.

    Once initialised, call the authenticate() method to authetnicate the user.

    Instance values of note:

        auth    (bool)  whether or not the user is authenticated
        reason  (str)   a string describing the current status
        code    (int)   return code (0 = auth:True, 1 = auth:False)
    """

    AuthError = AuthError

    def __init__(self, username: str, password: str):
        """Initialise things as a good init should.

        Call the authenticate() method to authenticate user.
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
        """Manually check tty.

        Check current tty against system secure ttys.
        """
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

        _pam = pam.pam()
        self.auth = _pam.authenticate(self.username, self.password,
                                      service=self.pam_service)
        self.reason = _pam.reason
        self.code = _pam.code

    def close(self):
        """Cleanup."""
        try:
            self._login_tmp.unlink()
        except (FileNotFoundError, PermissionError):
            pass

    def __del__(self):
        """Magic method to ensure that temp file is cleaned up."""
        self.close()
