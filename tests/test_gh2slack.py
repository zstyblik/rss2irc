#!/usr/bin/env python2
import logging
import time
import unittest

from mock import call, patch
import gh2slack

class MockedResponse(object):

    def __init__(self, response, headers=None):
        self.response = response
        if headers:
            self.headers = headers
        else:
            self.headers = {}

        self.status_code = 200
        self._raise_for_status_called = False

    def raise_for_status(self):
        self._raise_for_status_called = True

    def json(self):
        return self.response


class TestGH2slack(unittest.TestCase):

    def setUp(self):
        """Set up environment."""
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger()
        self.logger.disabled = True

    def test_assembly_slack_message(self):
        pass

    def test_get_gh_api_url(self):
        """Test get_gh_api_url()."""
        result = gh2slack.get_gh_api_url('foo', 'bar', 'lar')
        self.assertEqual(result, 'https://api.github.com/repos/foo/bar/lar')

    def test_get_gh_repository_url(self):
        """Test get_gh_repository_url()."""
        result = gh2slack.get_gh_repository_url('foo', 'bar')
        self.assertEqual(result, 'https://github.com/foo/bar')

    @patch('requests.get')
    def test_gh_request(self, mock_get):
        """Test gh_request()."""
        mocked_response = MockedResponse('foo')
        mock_get.return_value = mocked_response
        url = 'https://api.github.com/repos/foo/bar'
        response = gh2slack.gh_request(self.logger, url)
        self.assertEqual(response, ['foo'])
        self.assertEqual(
            mock_get.call_args[0],
            (url,)
        )
        self.assertTrue(mocked_response._raise_for_status_called)

    @patch('requests.get')
    def test_gh_request_follows_link_header(self, mock_get):
        """Test gh_request() follows up on 'Link' header."""
        url = 'https://api.github.com/repos/foo/bar'
        mocked_response1 = MockedResponse(
            'foo', {'link': '<http://example.com>; rel="next"'}
        )
        mocked_response2 = MockedResponse('bar', {'link': 'no-next'})
        mock_get.side_effect = [mocked_response1, mocked_response2]
        expected_mock_calls = [
            call(
                'https://api.github.com/repos/foo/bar',
                headers={'Accept': 'application/vnd.github.v3+json'},
                params={'sort': 'created', 'state': 'open'},
                timeout=30
            ),
            call(
                'http://example.com',
                headers={'Accept': 'application/vnd.github.v3+json'},
                params={'sort': 'created', 'state': 'open'},
                timeout=30
            ),
        ]

        response = gh2slack.gh_request(self.logger, url)
        self.assertEqual(response, ['foo', 'bar'])
        self.assertEqual(mock_get.mock_calls, expected_mock_calls)
        self.assertTrue(mocked_response1._raise_for_status_called)
        self.assertTrue(mocked_response2._raise_for_status_called)

    def test_process_page_items(self):
        pages = [
            [
                {
                    'html_url': 'http://example.com/foo',
                    'number': 0,
                    'title': 'some title#1',
                },
            ],
            [
                {
                    'html_url': 'http://example.com/bar',
                    'number': 1,
                    'title': 'some title#2',
                },
            ],
        ]
        repository_url = 'http://example.com'
        cache = {
            'http://example.com/bar': {
                'expiration': 0,
                'number': 1,
                'repository_url': repository_url,
                'title': 'some title#2',
            },
        }
        expiration = 20

        expected_cache = {
            'http://example.com/foo': {
                'expiration': expiration,
                'number': 0,
                'repository_url': repository_url,
                'title': 'some title#1',
            },
            'http://example.com/bar': {
                'expiration': expiration,
                'number': 1,
                'repository_url': repository_url,
                'title': 'some title#2',
            },
        }
        expected_to_publish = set(['http://example.com/foo'])

        to_publish = gh2slack.process_page_items(
            self.logger, cache, pages, expiration, repository_url
        )

        self.assertEqual(cache, expected_cache)
        self.assertEqual(to_publish, expected_to_publish)

    def test_scrub_cache(self):
        """Test scrub_cache()."""
        item_expiration = int(time.time()) + 60
        test_cache = {
            'foo': {
                'expiration': item_expiration,
            },
            'bar': {
                'expiration': int(time.time()) - 3600,
            },
            'lar': {
                'abc': 'efg',
            },
        }
        expected = {
            'foo': {
                'expiration': item_expiration,
            }
        }
        gh2slack.scrub_cache(self.logger, test_cache)
        self.assertEqual(test_cache, expected)
