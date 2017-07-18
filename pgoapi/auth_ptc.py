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

from requests.exceptions import RequestException, Timeout, ProxyError, SSLError, ConnectionError

class AuthPtc(Auth):

    PTC_LOGIN_URL1 = 'https://sso.pokemon.com/sso/oauth2.0/authorize'
    PTC_LOGIN_URL2 = 'https://sso.pokemon.com/sso/login'
    PTC_LOGIN_OAUTH = 'https://sso.pokemon.com/sso/oauth2.0/accessToken'
    PTC_LOGIN_CLIENT_SECRET = 'w8ScCUXJQc6kXKw8FiOhd8Fixzht18Dq3PEVkUCP5ZPxtgyWsbTvWHFLm2wNY0JR'

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

        get_params = {
            'client_id': 'mobile-app_pokemon-go',
            'redirect_uri': 'https://www.nianticlabs.com/pokemongo/error',
            'locale': self.locale
        }

        post_params = {
            'service': 'http://sso.pokemon.com/sso/oauth2.0/callbackAuthorize'
        }

        post_headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        try:
            now = get_time()

            r = self._session.get(self.PTC_LOGIN_URL1, params=get_params, timeout=self.timeout)

            data = r.json(encoding='utf-8')

            assert 'lt' in data
            data.update({
                '_eventId': 'submit',
                'username': self._username,
                'password': self._password
            })

            self._session.get('https://sso.pokemon.com/sso/logout', params={'service': 'https%3A%2F%2Fsso.pokemon.com%2Fsso%2Foauth2.0%2FcallbackAuthorize'}, timeout=self.timeout, allow_redirects=False)
            self._session.get('https://sso.pokemon.com/sso/login', params={'service': 'https%3A%2F%2Fsso.pokemon.com%2Fsso%2Foauth2.0%2FcallbackAuthorize', 'locale': self.locale}, timeout=self.timeout)

            r = self._session.post(self.PTC_LOGIN_URL2, params=post_params, headers=post_headers, data=data, timeout=self.timeout, allow_redirects=False)

            try:
                self._access_token = self._session.cookies['CASTGC']
            except (AttributeError, KeyError, TypeError):
                try:
                    j = r.json(encoding='utf-8')
                except ValueError as e:
                    raise AuthException('Unable to decode second response: {}'.format(e))
                try:
                    if j.get('error_code') == 'users.login.activation_required':
                        raise AuthException('Account email not verified.')
                    raise AuthException(j['errors'][0])
                except (AttributeError, IndexError, KeyError, TypeError) as e:
                    raise AuthException('Unable to login or get error information: {}'.format(e))

            token_data = {
                'client_id': 'mobile-app_pokemon-go',
                'redirect_uri': 'https://www.nianticlabs.com/pokemongo/error',
                'client_secret': self.PTC_LOGIN_CLIENT_SECRET,
                'grant_type': 'refresh_token',
                'code': r.headers['Location'].split("ticket=")[1]
            }
            self._session.post(self.PTC_LOGIN_OAUTH, headers=post_headers, data=token_data, timeout=self.timeout)

            profile_data = {
                'access_token': self._access_token,
                'client_id': 'mobile-app_pokemon-go',
                'locale': self.locale
            }
            self._session.post('https://sso.pokemon.com/sso/oauth2.0/profile', headers=post_headers, data=profile_data, timeout=self.timeout)

        except (ProxyError, SSLError, ConnectionError) as e:
            raise AuthException('Proxy connection error during user_login: {}'.format(e))
        except Timeout as e:
            raise AuthTimeoutException('User login procedure timeout.')
        except RequestException as e:
            raise AuthException('Caught RequestException: {}'.format(e))
        except (AssertionError, TypeError, ValueError) as e:
            raise AuthException('Invalid initial JSON response.')

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
        self.user_login()
        return self._access_token
