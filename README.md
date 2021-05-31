# zju-health-reporter

浙大钉钉自动健康打卡

This tool reports status to healthreport.zju.edu.cn after a random time within 2 minutes (can be skipped by specifying '--now')

A robot can be configured for result push..

Forked from [Tishacy/ZJU-nCov-Hitcarder](https://github.com/Tishacy/ZJU-nCov-Hitcarder)

CLI version for better implementation with crontab, schtasks, etc.

fixed "请求非法" due to python header

## prerequisite

```bash
$ pip3 install -r requirements.txt
```

## usage

```bash
$ python zju-health-reporter.py -h
usage: zju-health-reporter.py [-h] -u USERNAME -p PASSWORD [--now] [--telegram-token TELEGRAM_TOKEN]
                              [--telegram-chat_id TELEGRAM_CHAT_ID] [--telegram-proxy TELEGRAM_PROXY]
                              [--dingtalk-token DINGTALK_TOKEN] [--dingtalk-secret DINGTALK_SECRET]

This tool reports status to healthreport.zju.edu.cn

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME           username
  -p PASSWORD           password
  --now                 skip sleep time and execute now
  --telegram-token TELEGRAM_TOKEN
                        telegram token, see https://core.telegram.org/bots
  --telegram-chat_id TELEGRAM_CHAT_ID
                        telegram chat id, must be set with '--telegram-token'
  --telegram-proxy TELEGRAM_PROXY
                        telegram proxy like 'socks5://127.0.0.1:1080'
  --dingtalk-token DINGTALK_TOKEN
                        dingtalk access_token, see https://developers.dingtalk.com/document/app/custom-robot-access
  --dingtalk-secret DINGTALK_SECRET
                        dingtalk secret, must be set with '--dingtalk-token'
```

## example

run with assigned dingtalk bot

```
python3 zju-health-reporter.py -u "user" -p "password" --dingtalk-token "1234567890123456789012345678901234567890123456789012345678901234" --dingtalk-secret "SEC1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
```