#!/usr/bin/env python2
import logging
import time
import unittest

import rss2irc


class TestRSS2IRC(unittest.TestCase):

    def setUp(self):
        """Set up environment."""
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger()
        self.logger.disabled = True

    def test_scrub_cache(self):
        """Test scrub_cache()."""
        item_expiration = int(time.time()) + 60
        test_cache = {
            'foo': item_expiration,
            'bar': int(time.time()) - 3600,
            'lar': 'efg',
        }
        expected = {
            'foo': item_expiration,
        }
        rss2irc.scrub_cache(self.logger, test_cache)
        self.assertEqual(test_cache, expected)
