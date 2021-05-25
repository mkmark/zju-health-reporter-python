#!/usr/bin/env python3
import requests, json, re
import time, datetime
import io
import atexit
import logging
import random
import argparse

# %% logger

# # These two lines enable debugging at httplib level (requests->urllib3->http.client)
# # You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
# # The only thing missing will be the response.body which is not logged.
# import requests
# import logging
# try:
#     import http.client as http_client
# except ImportError:
#     # Python 2
#     import httplib as http_client
# http_client.HTTPConnection.debuglevel = 1

# # You must initialize logging, otherwise you'll not see debug output.
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

handler_console = logging.StreamHandler()
handler_console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler_console.setFormatter(formatter)

log_stringIO = io.StringIO()
handler_string = logging.StreamHandler(log_stringIO)
handler_string.setLevel(logging.INFO)
formatter = logging.Formatter('%(message)s')
handler_string.setFormatter(formatter)

logger.addHandler(handler_console)
logger.addHandler(handler_string)

# %% core
class HitCarder(object):
    """Hit carder class

    Attributes:
        username: (str) 浙大统一认证平台用户名（一般为学号）
        password: (str) 浙大统一认证平台密码
        login_url: (str) 登录url
        base_url: (str) 打卡首页url
        save_url: (str) 提交打卡url
        sess: (requests.Session) 统一的session
    """

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.login_url = "https://zjuam.zju.edu.cn/cas/login?service=https%3A%2F%2Fhealthreport.zju.edu.cn%2Fa_zju%2Fapi%2Fsso%2Findex%3Fredirect%3Dhttps%253A%252F%252Fhealthreport.zju.edu.cn%252Fncov%252Fwap%252Fdefault%252Findex"
        self.base_url = "https://healthreport.zju.edu.cn/ncov/wap/default/index"
        self.save_url = "https://healthreport.zju.edu.cn/ncov/wap/default/save"
        self.sess = requests.Session()
        self.sess.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'})

    def login(self):
        """Login to ZJU platform."""
        res = self.sess.get(self.login_url)
        execution = re.search('name="execution" value="(.*?)"', res.text).group(1)
        res = self.sess.get(url='https://zjuam.zju.edu.cn/cas/v2/getPubKey').json()
        n, e = res['modulus'], res['exponent']
        encrypt_password = self._rsa_encrypt(self.password, e, n)

        data = {
            'username': self.username,
            'password': encrypt_password,
            'execution': execution,
            'authcode': None,
            '_eventId': 'submit'
        }
        res = self.sess.post(url=self.login_url, data=data)
        # check if login successfully
        if '统一身份认证' in res.content.decode():
            raise LoginError('登录失败，请核实账号密码重新登录')
        return self.sess

    def post(self):
        """Post the hit card info."""
        res = self.sess.post(self.save_url, data=self.info)
        return json.loads(res.text)

    def get_date(self):
        """Get current date."""
        today = datetime.date.today()
        return "%4d%02d%02d" % (today.year, today.month, today.day)

    def get_info(self, html=None):
        """Get hit card info, which is the old info with updated new time."""
        if not html:
            res = self.sess.get(self.base_url)
            html = res.content.decode()

        try:
            old_infos = re.findall(r'oldInfo: ({[^\n]+})', html)
            if len(old_infos) != 0:
                old_info = json.loads(old_infos[0])
            else:
                raise RegexMatchError("未发现缓存信息，请先至少手动成功打卡一次再运行脚本")

            new_info_tmp = json.loads(re.findall(r'def = ({[^\n]+})', html)[0])
            new_id = new_info_tmp['id']
            name = re.findall(r'realname: "([^\"]+)",', html)[0]
            number = re.findall(r"number: '([^\']+)',", html)[0]
        except IndexError as err:
            raise RegexMatchError('Relative info not found in html with regex: ' + str(err))
        except json.decoder.JSONDecodeError as err:
            raise DecodeError('JSON decode error: ' + str(err))

        new_info = old_info.copy()
        new_info['id'] = new_id
        new_info['name'] = name
        new_info['number'] = number
        new_info["date"] = self.get_date()
        new_info["created"] = round(time.time())
        # form change
        new_info['jrdqtlqk[]'] = 0
        new_info['jrdqjcqk[]'] = 0
        new_info['sfsqhzjkk'] = 1  # 是否申领杭州健康码
        new_info['sqhzjkkys'] = 1  # 杭州健康吗颜色，1:绿色 2:红色 3:黄色
        new_info['sfqrxxss'] = 1  # 是否确认信息属实
        new_info['jcqzrq'] = ""
        new_info['gwszdd'] = ""
        new_info['szgjcs'] = ""
        self.info = new_info
        return new_info

    def _rsa_encrypt(self, password_str, e_str, M_str):
        password_bytes = bytes(password_str, 'ascii')
        password_int = int.from_bytes(password_bytes, 'big')
        e_int = int(e_str, 16)
        M_int = int(M_str, 16)
        result_int = pow(password_int, e_int, M_int)
        return hex(result_int)[2:].rjust(128, '0')

# Exceptions 
class LoginError(Exception):
    """Login Exception"""
    pass


class RegexMatchError(Exception):
    """Regex Matching Exception"""
    pass


class DecodeError(Exception):
    """JSON Decode Exception"""
    pass

# %% telegram_bot
class Telegram_bot():
    def ping(self, token, chat_id, text, proxy):
        url = 'http://api.telegram.org/bot' + token + '/sendMessage?chat_id=' + chat_id + '&text=' + text
        if proxy != "":
            proxies = {
                'https': proxy,
                'http': proxy
            }
            requests.get(url, proxies=proxies)
        else:
            requests.get(url)

# %% dingtalk bot
import time
import hmac
import hashlib
import base64
import urllib.parse
class Dingding_bot():
    def ping(self, access_token, secret, text):
        timestamp = str(round(time.time() * 1000))
        secret_enc = secret.encode('utf-8')
        string_to_sign = '{}\n{}'.format(timestamp, secret)
        string_to_sign_enc = string_to_sign.encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        url = "https://oapi.dingtalk.com/robot/send?access_token="+access_token+"&timestamp="+timestamp+"&sign="+sign
        headers = {'Content-Type': 'application/json'}
        data = '{"msgtype": "text","text": {"content":"'+text+'"}}'
        res=requests.post(url=url, data=data, headers=headers)
        #logger.info(res.content)

# %% parse args
parser = argparse.ArgumentParser(description="""
This tool report status to healthreport.zju.edu.cn
""")
parser.add_argument("-u", dest = "USERNAME", \
                          help = "username", \
                          required = True)
parser.add_argument("-p", dest = "PASSWORD", \
                          help = "password", \
                          required = True)
parser.add_argument("--telegram-token", default = "", \
                          dest = "TELEGRAM_TOKEN", \
                          help = "telegram token, like \"123456789:ABcsdsfarwegssrgw3erw34gbw5b5rw2\"", \
                          required = False)
parser.add_argument("--telegram-chat_id", default = "", \
                          dest = "TELEGRAM_CHAT_ID", \
                          help = "telegram chat id, like \"-12345678\"", \
                          required = False)
parser.add_argument("--telegram-proxy", default = "", \
                          dest = "TELEGRAM_PROXY", \
                          help = "telegram proxy like \'socks5://127.0.0.1:1080\'", \
                          required = False)
parser.add_argument("--dingtalk-token", default = "", \
                          dest = "DINGTALK_TOKEN", \
                          help = "dingtalk access_token, see https://developers.dingtalk.com/document/app/custom-robot-access", \
                          required = False)
parser.add_argument("--dingtalk-secret", default = "", \
                          dest = "DINGTALK_SECRET", \
                          help = "dingtalk secret, see https://developers.dingtalk.com/document/app/custom-robot-access", \
                          required = False)

# %% main
if __name__ == '__main__':
    args = parser.parse_args()
    username = args.USERNAME
    logger.info('task start: ' + username)
    password = args.PASSWORD
    telegram_token = args.TELEGRAM_TOKEN
    telegram_chat_id = args.TELEGRAM_CHAT_ID
    telegram_proxy = args.TELEGRAM_PROXY
    dingtalk_token = args.DINGTALK_TOKEN
    dingtalk_secret = args.DINGTALK_SECRET

    def exit_handler():
        # telegram_bot
        if telegram_token != "":
            telegram_bot = Telegram_bot()
            telegram_bot.ping(telegram_token, telegram_chat_id, log_stringIO.getvalue(), telegram_proxy)
        if dingtalk_token != "":
            dingtalk_bot = Dingding_bot()
            dingtalk_bot.ping(dingtalk_token, dingtalk_secret, log_stringIO.getvalue())

    atexit.register(exit_handler)

    # sleep random
    sleep_time = random.randint(0,120)
    logger.info('sleep %s sec', sleep_time)
    # Wait for sleep_time seconds
    time.sleep(sleep_time)

    # login
    hit_carder = HitCarder(username, password)
    temp = hit_carder.login()

    # get info
    temp = hit_carder.get_info()

    # post
    time.sleep(5)
    res = hit_carder.post()
    if str(res['e']) == '0':
        logger.info('task finished successfully')
    elif str(res['m']) == '今天已经填报了':
        logger.info('task already finished today')
    else:
        logger.info('task failed')
