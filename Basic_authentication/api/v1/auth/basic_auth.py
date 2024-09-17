#!/usr/bin/env python3
""" 6. Basic auth
"""

from api.v1.auth.auth import Auth
import base64
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """ BasicAuth class.
    """

    def extract_base64_authorization_header(self, ah: str) -> str:
        """ def extract_base64_authorization_header.
        """
        if not ah or type(ah) != str or not ah.startswith("Basic "):
            return
        return "".join(ah.split(" ")[1:])

    def decode_base64_authorization_header(self, b64: str) -> str:
        """ def decode_base64_authorization_header.
        """
        if not b64 or type(b64) != str:
            return
        try:
            b64_bytes = b64.encode('utf-8')
            res = base64.b64decode(b64_bytes)
            return res.decode('utf-8')
        except Exception:
            return

    def extract_user_credentials(self, db64: str) -> (str, str):
        """ def extract_user_credentials.
        """
        if not db64 or type(db64) != str or ":" not in db64:
            return (None, None)
        a, b = db64.split(':')[0], "".join(db64.split(':', 1)[1:])
        return (a, b)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """ def user_object_from_credentials.
        """
        if (not user_email or
                type(user_email) != str or
                not user_pwd or type(user_pwd) != str):
            return
        user = None
        try:
            user = User.search({"email": user_email})
        except Exception:
            return
        if not user:
            return
        for u in user:
            if u.is_valid_password(user_pwd):
                return u

    def current_user(self, request=None) -> TypeVar('User'):
        """ def current_user.
        """
        header = self.authorization_header(request)
        b64header = self.extract_base64_authorization_header(header)
        decoded = self.decode_base64_authorization_header(b64header)
        user_creds = self.extract_user_credentials(decoded)
        return self.user_object_from_credentials(*user_creds)
