#!/usr/bin/env python
# -*- coding:utf-8 -*-

import pytest
from httmock import all_requests, HTTMock
from oncallclient import OncallClient


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
    mocker.patch('oncallclient.time').time.return_value = 1000

    OncallClient(
        app='SERVICE_FOO',
        key='ONCALL_API_KEY',
        api_host='http://oncall.foo.bar'
    )

    client = OncallClient(
        app=b'SERVICE_FOO',
        key=b'ONCALL_API_KEY',
        api_host='http://oncall.foo.bar'
    )

    @all_requests
    def check_auth_header(url, request):
        header_bytes = bytes(request.headers['Authorization'])
        assert header_bytes.startswith('hmac SERVICE_FOO:'.encode('utf-8'))
        return {'status_code': 200, 'content': '{}'}

    with HTTMock(check_auth_header):
        client.get_team('example')

