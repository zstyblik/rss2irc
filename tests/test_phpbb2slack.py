#!/usr/bin/env python
import logging
import os
import time
import unittest

import phpbb2slack


class TestPHPBB2Slack(unittest.TestCase):

    def setUp(self):
        """Set up environment."""
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger()
        self.logger.disabled = True

    def test_format_message(self):
        """Test format_message()."""
        test_data = [
            {
                'url': 'http://www.example.com',
                'attrs': {
                    'category': 'test',
                    'comments_cnt': 12,
                    'title': 'someTitle',
                },
                'handle': 'someHandle',
                'expected': '[someHandle-test] someTitle (12) | http://www.example.com\n',
            },
            {
                'url': 'http://www.example.com',
                'attrs': {
                    'category': '',
                    'comments_cnt': 1,
                    'title': 'someTitle',
                },
                'handle': 'someHandle',
                'expected': '[someHandle] someTitle (1) | http://www.example.com\n',
            },
        ]
        for data in test_data:
            message = phpbb2slack.format_message(
                data['url'], data['attrs'], data['handle']
            )
            self.assertEqual(message, data['expected'])

    def test_get_authors_from_file(self):
        """Test get_authors_from_file()."""
        authors_file = os.path.join(
            os.path.dirname(__file__), 'files', 'authors.txt'
        )
        expected_authors = [
            'author1',
            'author2',
        ]
        authors = phpbb2slack.get_authors_from_file(self.logger, authors_file)
        self.assertEqual(authors, expected_authors)

    def test_get_authors_from_file_no_file(self):
        """Test get_authors_from_file() when no file is given."""
        authors_file = ''
        expected_authors = []
        authors = phpbb2slack.get_authors_from_file(self.logger, authors_file)
        self.assertEqual(authors, expected_authors)

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
        phpbb2slack.scrub_cache(self.logger, test_cache)
        self.assertEqual(test_cache, expected)

    def test_update_cache(self):
        """Test update_cache()."""
        item_expiration = int(time.time()) + 60
        news = {
            'http://example.com': {
                'comments_cnt': 2,
            },
            'http://www.example.com': {
                'comments_cnt': 20,
            },
        }
        cache = {
            'http://example.com': {
                'expiration': 0,
                'comments_cnt': 1,
            },
        }
        expected_cache = {
            'http://example.com': {
                'expiration': item_expiration,
                'comments_cnt': 2,
            },
            'http://www.example.com': {
                'expiration': item_expiration,
                'comments_cnt': 20,
            },
        }
        phpbb2slack.update_cache(cache, news, item_expiration)
        self.assertEqual(cache, expected_cache)
