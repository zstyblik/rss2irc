#!/usr/bin/env python2
import logging
import time
import unittest

from mock import patch
import gh2slack

class MockedResponse(object):

    def __init__(self, response):
        self.response = response
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

    @patch('requests.get')
    def test_gh_request(self, mock_get):
        """Test gh_request()."""
        mocked_response = MockedResponse('foo')
        mock_get.return_value = mocked_response
        uri = 'foo/bar'
        response = gh2slack.gh_request(self.logger, uri)
        self.assertEqual(response, 'foo')
        self.assertEqual(
            mock_get.call_args[0],
            ('https://api.github.com/repos/{}'.format(uri),)
        )
        self.assertTrue(mocked_response._raise_for_status_called)

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
