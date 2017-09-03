# RSS2IRC

RSS2IRC is a Python script to feed RSS news to IRC bot, resp. [ii IRC bot], or write to file. News URL are cached into file in order to eliminate repetition. Some sites like to change titles or re-post news for whatever reason. It's also way how to keep track of delta.

### Usage
```
./rss2irc.py \
    --rss-url http://www.example.com/rss \
    --out '/opt/iibot/irc.network.com/#channel/in' \
    --cache /tmp/example.cache
```

# RSS2slack

RSS2slack is the same thing, but for [slack].

### Usage

```
export SLACK_TOKEN=abc123
./rss2slack.py \
    --rss-url http://www.example.com/rss \
    --slack-channel test \
    --cache /tmp/example.cache
```

[ii IRC bot]: http://tools.suckless.org/ii/
[slack]: https://www.slack.com
