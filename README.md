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
$ python zjuhealth.py
usage: zjuhealth.py [-h] -u USERNAME -p PASSWORD [--telegram-token TELEGRAM_TOKEN]
                    [--telegram-chat_id TELEGRAM_CHAT_ID] [--telegram-proxy TELEGRAM_PROXY]
```
