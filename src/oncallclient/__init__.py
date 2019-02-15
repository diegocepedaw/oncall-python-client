from __future__ import absolute_import

from .compat import str, bytes

import base64
import hashlib
import hmac
import time

import requests


__version__ = "1.1.0"


class OncallAuth(requests.auth.AuthBase):
    def __init__(self, app, key):
        if not isinstance(app, bytes):
            app = app.encode('utf-8')
        self.header = b'hmac ' + app + b':'
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        self.HMAC = hmac.new(key, b'', hashlib.sha512)

    def __call__(self, request):
        HMAC = self.HMAC.copy()
        path = str(request.path_url)
        method = str(request.method)
        body = str(request.body or '')
        window = str(int(time.time()) // 5)
        content = '%s %s %s %s' % (window, method, path, body)
        HMAC.update(content.encode('utf-8'))
        digest = base64.urlsafe_b64encode(HMAC.digest())
        request.headers['Authorization'] = self.header + digest
        return request


class OncallClient(requests.Session):
    def __init__(self, app, key, api_host, version=0):
        super(OncallClient, self).__init__()
        self.app = app
        self.auth = OncallAuth(app, key)
        self.url = api_host + '/api/v%d/' % version

    def get_user(self, username):
        r = self.get(self.url + 'users/%s' % username)
        r.raise_for_status()
        try:
            return r.json()
        except:
            raise ValueError('Failed to decode json: %s' % r.text)

    def get_user_teams(self, username):
        r = self.get(self.url + 'users/%s/teams' % username)
        r.raise_for_status()
        try:
            return r.json()
        except:
            raise ValueError('Failed to decode json: %s' % r.text)

    def get_team(self, team):
        r = self.get(self.url + 'teams/%s' % team)
        r.raise_for_status()
        try:
            return r.json()
        except:
            raise ValueError('Failed to decode json: %s' % r.text)

    def all_teams(self, team):
        r = self.get(self.url + 'teams')
        r.raise_for_status()
        try:
            return r.json()
        except:
            raise ValueError('Failed to decode json: %s' % r.text)

    def get_oncall_now(self, team, role=None):
        if role is None:
            roles = ''
        else:
            roles = '/%s' % role
        r = self.get(self.url + 'teams/%s/oncall%s' % (team, roles))
        r.raise_for_status()
        try:
            return r.json()
        except:
            raise ValueError('Failed to decode json: %s' % r.text)

    def get_events(self, **kwargs):
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        r = self.get(self.url + 'events', params=kwargs)
        r.raise_for_status()
        try:
            return r.json()
        except:
            raise ValueError('Failed to decode json: %s' % r.text)

    def all_roles(self):
        r = self.get(self.url + 'roles')
        r.raise_for_status()
        try:
            return r.json()
        except:
            raise ValueError('Failed to decode json: %s' % r.text)

    def get_audit(self, **kwargs):
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        r = self.get(self.url + 'audit', params=kwargs)
        r.raise_for_status()
        try:
            return r.json()
        except:
            raise ValueError('Failed to decode json: %s' % r.text)

    def get_suggestion(self, team, roster, role, start, end):
        r = self.get(self.url + 'teams/%s/rosters/%s/%s/suggest?start=%s&end=%s' %
                     (team, roster, role, start, end))
        r.raise_for_status()
        try:
            return r.json()
        except:
            raise ValueError('Failed to decode json: %s' % r.text)

