# zju-health-reporter

浙大钉钉自动健康打卡

This tool reports status to healthreport.zju.edu.cn after a random time within 2 minutes (can be skipped by specifying '--now')

Forked from [Tishacy/ZJU-nCov-Hitcarder](https://github.com/Tishacy/ZJU-nCov-Hitcarder)

CLI version for better implementation with crontab, schtasks, etc.

A robot can be configured for result push.

## prerequisite

```bash
$ pip install requests
```

## usage

```bash
$ python zju-health-reporter.py -h
usage: zju-health-reporter.py [-h] -u USERNAME -p PASSWORD [--address ADDRESS] [--area AREA] [--city CITY] [--now]
                              [--telegram-token TELEGRAM_TOKEN] [--telegram-chat_id TELEGRAM_CHAT_ID]
                              [--telegram-proxy TELEGRAM_PROXY] [--dingtalk-token DINGTALK_TOKEN]
                              [--dingtalk-secret DINGTALK_SECRET]

This tool reports status to healthreport.zju.edu.cn

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME           username
  -p PASSWORD           password
  --address ADDRESS     address override
  --area AREA           area override
  --city CITY           city override
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

beta: if prompted 'require additional location info', you will have to input your location manually. See example.

## example

minimun instant run

```
python3 zju-health-reporter.py -u "user" -p "password" --now
```

run with assigned dingtalk bot

```
python3 zju-health-reporter.py -u "user" -p "password" --dingtalk-token "1234567890123456789012345678901234567890123456789012345678901234" --dingtalk-secret "SEC1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
```

beta: manually override location info:

```
python3 zju-health-reporter.py -u "user" -p "password" --dingtalk-token "1234567890123456789012345678901234567890123456789012345678901234" --dingtalk-secret "SEC1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" --address "浙江省嘉兴市海宁市硖石街道西粮路浙江大学海宁国际校区" --area "浙江省 嘉兴市 海宁市" --city "嘉兴市"
```

the program works best with [crontab](https://en.wikipedia.org/wiki/Cron) / schtasks (Windows Task scheduler, Windows计划任务程序)
