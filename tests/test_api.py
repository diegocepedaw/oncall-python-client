#!/usr/bin/env python
# -*- coding:utf-8 -*-

import pytest
from httmock import all_requests, HTTMock
from oncallclient import OncallClient
import hmac
import hashlib
import base64


path_to_resp = {
    '/api/v0/users/jdoe': {
        'status_code': 200,
        'content': '{"name": "jdoe"}'
    },
    '/api/v0/teams/example': {
        'status_code': 200,
        'content': '{"name": "example"}'
    }
}


@all_requests
def mock_response(url, request):
    return path_to_resp[url.path]


@pytest.fixture
def oncall_client():
    return OncallClient(
        app='SERVICE_FOO',
        key='ONCALL_API_KEY',
        api_host='http://oncall.foo.bar'
    )


def test_get_user(oncall_client):
    with HTTMock(mock_response):
        re = oncall_client.get_user('jdoe')
        assert re['name'] == 'jdoe'


def test_get_team(oncall_client):
    with HTTMock(mock_response):
        re = oncall_client.get_team('example')
        assert re['name'] == 'example'


def test_encoding_in_hmac(mocker):
    mocker.patch('time.time', mocker.MagicMock(return_value=1000))

    client = OncallClient(
        app=b'SERVICE_FOO',
        key=b'ONCALL_API_KEY',
        api_host='http://oncall.foo.bar'
    )

    @all_requests
    def check_get_header(url, request):
        header_bytes = bytes(request.headers['Authorization'])
        assert header_bytes.startswith('hmac SERVICE_FOO:'.encode('utf-8'))
        assert header_bytes == b'hmac SERVICE_FOO:CvnjgxM_f3m_2BbokJLKiQ3_3b57arO44EmCqkkHgmIcRosYyYQF9BCkbpm15ePNLIblyM8OZ4UPkJYkOKhx7Q=='
        return {'status_code': 200, 'content': '{}'}

    with HTTMock(check_get_header):
        client.get_team('example')

    @all_requests
    def check_post_header(url, request):
        header_bytes = request.headers['Authorization']
        HMAC = hmac.new(b'ONCALL_API_KEY', b'', hashlib.sha512)
        path = b'/api/v0/events'
        method = b'POST'
        body = request.body or b''
        window = b'200'
        HMAC.update(b'%s %s %s %s' % (window, method, path, body))
        digest = base64.urlsafe_b64encode(HMAC.digest())
        assert header_bytes == b'hmac SERVICE_FOO:%s' % digest
        return {'status_code': 200, 'content': '{}'}
    with HTTMock(check_post_header):
        client.create_event('team', 'user', 0, 100, 'role')

