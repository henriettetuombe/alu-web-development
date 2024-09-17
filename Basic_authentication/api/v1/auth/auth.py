#!/usr/bin/env python3
"""
Auth class
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """ Auth class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ require_auth
        """
        if path is None:
            return True
        if excluded_paths is None or excluded_paths == []:
            return True
        path = path + '/' if path[-1] != '/' else path
        excluded_paths = [excluded + '/' if excluded[-1] != '/' else excluded
                          for excluded in excluded_paths]

        if path not in excluded_paths:
            return True
        else:
            return False

    def authorization_header(self, request=None) -> str:
        """ authorization_header
        """
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user
        """
        return None
