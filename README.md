# zjuhealth

Forked from [Tishacy/ZJU-nCov-Hitcarder](https://github.com/Tishacy/ZJU-nCov-Hitcarder)

CLI version for better implementation with crontab, schtasks, etc.

fixed "请求非法" due to python header

## prerequisite

```bash
$ pip3 install -r requirements.txt
```

## usage

```bash
$ python zjuhealth.py -h
usage: zjuhealth.py [-h] -u USERNAME -p PASSWORD [--telegram-token TELEGRAM_TOKEN]
                    [--telegram-chat_id TELEGRAM_CHAT_ID] [--telegram-proxy TELEGRAM_PROXY]
                    [--dingding-token DINGDING_TOKEN] [--dingding-secret DINGDING_SECRET]

This tool report status to healthreport.zju.edu.cn

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME           username, see https://zjuam.zju.edu.cn/cas/login
  -p PASSWORD           password, see https://zjuam.zju.edu.cn/cas/login
  --telegram-token TELEGRAM_TOKEN
                        telegram token, like "123456789:ABcsdsfarwegssrgw3erw34gbw5b5rw2"
  --telegram-chat_id TELEGRAM_CHAT_ID
                        telegram chat id, like "-12345678"
  --telegram-proxy TELEGRAM_PROXY
                        telegram proxy like 'socks5://127.0.0.1:1080'
  --dingding-token DINGDING_TOKEN
                        dingding access_token, see https://developers.dingtalk.com/document/app/custom-
                        robot-access
  --dingding-secret DINGDING_SECRET
                        dingding secret, see https://developers.dingtalk.com/document/app/custom-robot-
                        access
```
