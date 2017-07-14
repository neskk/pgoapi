"""
pgoapi - Pokemon Go API
Copyright (c) 2016 tjado <https://github.com/tejado>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.

Author: tjado <https://github.com/tejado>
"""

from __future__ import absolute_import
from future.standard_library import install_aliases
install_aliases()

import requests

from urllib.parse import parse_qs, urlsplit
from six import string_types

from pgoapi.auth import Auth
from pgoapi.utilities import get_time
from pgoapi.exceptions import AuthException, AuthTimeoutException, InvalidCredentialsException

from requests.exceptions import RequestException, Timeout

class AuthPtc(Auth):

    def __init__(self, username=None, password=None, user_agent=None, timeout=None, locale=None):
        Auth.__init__(self)

        self._auth_provider = 'ptc'

        self._username = username
        self._password = password

        self.locale = locale or 'en_US'
        self.timeout = timeout or 10

        self._session = requests.session()

        self._session.headers = {
            'Accept': '*/*',
            'Host': 'sso.pokemon.com',
            'Connection': 'keep-alive',
            'User-Agent': user_agent or 'pokemongo/1 CFNetwork/811.4.18 Darwin/16.5.0',
            'Accept-Language': self.locale.lower().replace('_', '-'),
            'Accept-Encoding': 'gzip-deflate',
            'X-Unity-Version': '5.5.1f1'
        }

    def set_proxy(self, proxy_config):
        self._session.proxies = proxy_config

    def user_login(self, username=None, password=None):
        self._username = username or self._username
        self._password = password or self._password
        if not isinstance(self._username, string_types) or not isinstance(self._password, string_types):
            raise InvalidCredentialsException("Username/password not correctly specified")

        self.log.info('PTC User Login for: {}'.format(self._username))
        self._session.cookies.clear()
        now = get_time()

        try:
            r = self._session.get('https://sso.pokemon.com/sso/oauth2.0/authorize', params={'client_id': 'mobile-app_pokemon-go', 'redirect_uri': 'https://www.nianticlabs.com/pokemongo/error', 'locale': self.locale}, timeout=self.timeout)
        except Timeout:
            raise AuthTimeoutException('Auth GET timed out.')
        except RequestException as e:
            raise AuthException('Caught RequestException: {}'.format(e))

        try:
            data = r.json(encoding='utf-8')
            assert 'lt' in data
            data.update({
                '_eventId': 'submit',
                'username': self._username,
                'password': self._password,
                'locale': self.locale
            })
        except (AssertionError, ValueError, AttributeError) as e:
            self.log.error('PTC User Login Error - invalid initial JSON response: {}'.format(e))
            raise AuthException('Invalid initial JSON response: {}'.format(e))

        try:
            r = self._session.post('https://sso.pokemon.com/sso/login', params={'service': 'http://sso.pokemon.com/sso/oauth2.0/callbackAuthorize'}, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=data, timeout=self.timeout, allow_redirects=False)
        except Timeout:
            raise AuthTimeoutException('Auth POST timed out.')
        except RequestException as e:
            raise AuthException('Caught RequestException: {}'.format(e))

        self._access_token = self._session.cookies.get('CASTGC')

        if self._access_token:
            self._login = True
            self._access_token_expiry = now + 7195.0
            self.log.info('PTC User Login successful.')
            return self._login

        self._login = False
        raise AuthException("Could not retrieve a PTC Access Token")


    def get_access_token(self, force_refresh=False):
        if not force_refresh and self.check_access_token():
            self.log.debug('Using cached PTC Access Token')
            return self._access_token

        self._access_token = None
        self._login = False
        return self.user_login(retry=False)
