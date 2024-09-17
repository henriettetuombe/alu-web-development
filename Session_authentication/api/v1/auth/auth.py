#!/usr/bin/env python3
""" 3. Auth class
"""

from flask import request
from os import getenv
from typing import List, TypeVar


class Auth:
    """ Auth class.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ require_auth
        """
        if not path or not excluded_paths:
            return True
        path = path + '/' if path[-1] != '/' else path
        has_wildcard = any(x.endswith("*") for x in excluded_paths)
        if not has_wildcard:
            return path not in excluded_paths
        for e in excluded_paths:
            if e.endswith("*"):
                if path.startswith(e[:-1]):
                    return False
            if path == e:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ authorization_header
        """
        if request:
            return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user
        """
        return None

    def session_cookie(self, request=None):
        """ session_cookie
        """
        if request:
            session_name = getenv("SESSION_NAME")
            return request.cookies.get(session_name, None)
