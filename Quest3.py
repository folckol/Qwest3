import base64
import json
import pprint
import random
import re
import ssl
import requests
import cloudscraper

import capmonster_python
import time
from web3.auto import w3
from eth_account.messages import encode_defunct
import os
from TwitterModel import Account

class Discord:

    def __init__(self, token, proxy, cap_key):

        self.cap = capmonster_python.HCaptchaTask(cap_key)
        self.token = token
        self.proxy = proxy

        # print(token)
        # print(proxy)
        # print(cap_key)

        self.session = self._make_scraper()
        self.ua = random_user_agent()
        self.session.user_agent = self.ua
        self.super_properties = self.build_xsp(self.ua)
        self.session.proxies = self.proxy

        self.cfruid, self.dcfduid, self.sdcfduid = self.fetch_cookies(self.ua)
        self.fingerprint = self.get_fingerprint()


    def JoinServer(self, invite):

        rer = self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token})

        # print(rer.text, rer.status_code)
        # print(rer.text)
        # print(rer.status_code)

        if "200" not in str(rer):
            site = "a9b5fb07-92ff-493f-86fe-352a2803b3df"
            tt = self.cap.create_task("https://discord.com/api/v9/invites/" + invite, site)
            # print(f"Created Captcha Task {tt}")
            captcha = self.cap.join_task_result(tt)
            captcha = captcha["gRecaptchaResponse"]
            # print(f"[+] Solved Captcha ")
            # print(rer.text)

            self.session.headers = {'Host': 'discord.com', 'Connection': 'keep-alive',
                               'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                               'X-Super-Properties': self.super_properties,
                               'Accept-Language': 'en-US', 'sec-ch-ua-mobile': '?0',
                               "User-Agent": self.ua,
                               'Content-Type': 'application/json', 'Authorization': 'undefined', 'Accept': '*/*',
                               'Origin': 'https://discord.com', 'Sec-Fetch-Site': 'same-origin',
                               'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
                               'Referer': 'https://discord.com/@me', 'X-Debug-Options': 'bugReporterEnabled',
                               'Accept-Encoding': 'gzip, deflate, br',
                               'x-fingerprint': self.fingerprint,
                               'Cookie': f'__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; __cf_bm=DFyh.5fqTsl1JGyPo1ZFMdVTupwgqC18groNZfskp4Y-1672630835-0-Aci0Zz919JihARnJlA6o9q4m5rYoulDy/8BGsdwEUE843qD8gAm4OJsbBD5KKKLTRHhpV0QZybU0MrBBtEx369QIGGjwAEOHg0cLguk2EBkWM0YSTOqE63UXBiP0xqHGmRQ5uJ7hs8TO1Ylj2QlGscA='}
            rej = self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token}, json={
                "captcha_key": captcha,
                "captcha_rqtoken": str(rer.json()["captcha_rqtoken"])
            })
            # print(rej.text())
            # print(rej.status_code)
            if "200" in str(rej):
                return 'Successfully Join 0', self.super_properties
            if "200" not in str(rej):
                return 'Failed Join'

        else:
            with self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token}) as response:
                # print(response.text)
                pass
            return 'Successfully Join 1', self.super_properties


    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

    def build_xsp(self, ua):
        # ua = get_useragent()
        _,fv = self.get_version(ua)
        data = json.dumps({
            "os": "Windows",
            "browser": "Chrome",
            "device": "",
            "system_locale": "en-US",
            "browser_user_agent": ua,
            "browser_version": fv,
            "os_version": "10",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": self.get_buildnumber(),
            "client_event_source": None
        }, separators=(",",":"))
        return base64.b64encode(data.encode()).decode()

    def get_version(self, user_agent):  # Just splits user agent
        chrome_version = user_agent.split("/")[3].split(".")[0]
        full_chrome_version = user_agent.split("/")[3].split(" ")[0]
        return chrome_version, full_chrome_version

    def get_buildnumber(self):  # Todo: make it permanently work
        r = requests.get('https://discord.com/app', headers={'User-Agent': 'Mozilla/5.0'})
        asset = re.findall(r'([a-zA-z0-9]+)\.js', r.text)[-2]
        assetFileRequest = requests.get(f'https://discord.com/assets/{asset}.js',
                                        headers={'User-Agent': 'Mozilla/5.0'}).text
        try:
            build_info_regex = re.compile('buildNumber:"[0-9]+"')
            build_info_strings = build_info_regex.findall(assetFileRequest)[0].replace(' ', '').split(',')
        except:
            # print("[-]: Failed to get build number")
            pass
        dbm = build_info_strings[0].split(':')[-1]
        return int(dbm.replace('"', ""))

    def fetch_cookies(self, ua):
        try:
            url = 'https://discord.com/'
            headers = {'user-agent': ua}
            response = self.session.get(url, headers=headers, proxies=self.proxy)
            cookies = response.cookies.get_dict()
            cfruid = cookies.get("__cfruid")
            dcfduid = cookies.get("__dcfduid")
            sdcfduid = cookies.get("__sdcfduid")
            return cfruid, dcfduid, sdcfduid
        except:
            # print(response.text)
            return 1

    def get_fingerprint(self):
        try:
            fingerprint = self.session.get('https://discord.com/api/v9/experiments', proxies=self.proxy).json()['fingerprint']
            # print(f"[=]: Fetched Fingerprint ({fingerprint[:15]}...)")
            return fingerprint
        except Exception as err:
            # print(err)
            return 1





def random_user_agent():
    browser_list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.{1}.{2} Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{2}_{3}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{1}.{2}) Gecko/20100101 Firefox/{1}.{2}',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.{1}.{2} Edge/{3}.{4}.{5}'
    ]

    chrome_version = random.randint(70, 108)
    firefox_version = random.randint(70, 108)
    safari_version = random.randint(605, 610)
    edge_version = random.randint(15, 99)

    chrome_build = random.randint(1000, 9999)
    firefox_build = random.randint(1, 100)
    safari_build = random.randint(1, 50)
    edge_build = random.randint(1000, 9999)

    browser_choice = random.choice(browser_list)
    user_agent = browser_choice.format(chrome_version, firefox_version, safari_version, edge_version, chrome_build, firefox_build, safari_build, edge_build)

    return user_agent


class QuestAccount:

    def __init__(self, proxy, address, tw_auth_token, tw_csrf, private, dsToken):

        self.discord_token = dsToken

        self.defaultProxy = proxy
        proxy = proxy.split(':')
        proxy = f'http://{proxy[2]}:{proxy[3]}@{proxy[0]}:{proxy[1]}'

        self.proxy = {'http': proxy,
                           'https': proxy}
        print(self.proxy)

        self.private = private
        self.address = address

        self.auth_token = tw_auth_token
        self.csrf = tw_csrf

        self.session = self._make_scraper()
        self.session.proxies = self.proxy
        self.session.user_agent = random_user_agent()
        adapter = requests.adapters.HTTPAdapter(max_retries=5)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)




    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

    def login(self):

        # with session.get('https://app.quest3.xyz/quest/745814372281045400', timeout=15) as response:
        #     print(response.text)

        timestamp = int(time.time())
        print(timestamp)
        message = encode_defunct(
            text=f'Welcome to QuestN.\nPlease sign this message to login QuestN.\n\nTimestamp: {timestamp}')
        signed_message = w3.eth.account.sign_message(message, private_key=self.private)
        signature = signed_message["signature"].hex()
        print(signature)

        self.session.headers.update({'Host': 'api.questn.com',
                                'Content-Length': '326',
                                'Content-Type': 'application/json',
                                'Accept': 'application/json, text/plain, */*',
                                'Origin': 'https://app.questn.com',
                                'Referer': 'https://app.questn.com/'
                                })
        payload = {'address': self.address,
                   'login_type': 100,
                   'message': f'Welcome to QuestN.\nPlease sign this message to login QuestN.',
                   'photo': random.randint(1, 12),
                   'signature': signature[2:],
                   'timestamp': timestamp}

        with self.session.post('https://api.questn.com/user/login/', json=payload, timeout=15,
                          allow_redirects=False) as response:
            # print(response.headers)
            # print(response.status_code)
            print(response.json())
            if response.json()['success']:

                self.session.headers.clear()

                self.session.headers.update({'ACCESS-TOKEN': response.json()['result']['access_token']})
                self.user_id = response.json()['result']['user_info']['id']
                return response.json()
            else:
                return False

    def RafflesList(self, page=1):

        self.session.headers.update({'Accept': 'application/json, text/plain, */*'})

        # print(self.session.headers)

        with self.session.get(f'https://api.questn.com/consumer/quest/discover_list/?count=100&page={page}&search=&category=100&status_filter=100&community_filter=0&rewards_filter=0&tag_filter=0&user_id={self.user_id}', timeout=15) as response:

            # print(response.json())
            return response.json()['result']['data']

    def GetRaffleInfo(self, id_):

        # self.session.headers.update({'Accept': 'application/json, text/plain, */*'})

        # print(self.session.headers)

        with self.session.get(f'https://api.questn.com/consumer/quest/info/?quest_id={id_}&user_id={self.user_id}&flag=0', timeout=15) as response:

            # print(response.json())
            return response.json()


    def ConnectDiscord(self):
        url = 'https://discord.com/oauth2/authorize?client_id=974630353622933535&redirect_uri=https%3A%2F%2Fapp.questn.com%2Fauth&response_type=code&scope=identify%20email%20guilds%20guilds.members.read&state=200%2B2'

        with self.session.get(url, timeout=15) as response:
            # print(response.text)
            # input()

            state = url.split('state=')[-1].split('&')[0]
            client_id = url.split('client_id=')[-1].split('&')[0]

            discord_headers = {
                'authority': 'discord.com',
                'authorization': self.discord_token,
                'content-type': 'application/json',
                'referer': f'https://discord.com/oauth2/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.questn.com%2Fauth&response_type=code&scope=identify%20email%20guilds%20guilds.members.read&state={state}',
                'x-super-properties': 'eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJydS1SVSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMDkuMC4wLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwOS4wLjAuMCIsIm9zX3ZlcnNpb24iOiIxMC4xNS43IiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjE3NDA1MSwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbCwiZGVzaWduX2lkIjowfQ==',
            }

            payload = {"permissions": "0", "authorize": True}

            with self.session.post(
                    f'https://discord.com/api/v9/oauth2/authorize?client_id={client_id}&response_type=code&redirect_uri=https%3A%2F%2Fapp.questn.com%2Fauth&scope=identify%20email%20guilds%20guilds.members.read&state={state}',
                    json=payload, timeout=15, headers=discord_headers) as response:
                url = response.json()['location']
                print(url)
                code = url.split('code=')[-1].split('&')[0]

                with self.session.get(url, timeout=15) as response:

                    payload = {"code":code,"login_type":200}

                    with self.session.post('https://api.questn.com/user/auth/bind/', json=payload, timeout=15) as response:

                        if response.json()['success'] == True:
                            print(f'Discord connected')
                        else:
                            print(response.json())




    def ConnectTwitter(self):
        url = 'https://twitter.com/i/oauth2/authorize?client_id=R2hWS0VKTlNsNGJEalg3SjFwOFU6MTpjaQ&redirect_uri=https%3A%2F%2Fapp.questn.com%2Fauth&response_type=code&scope=tweet.read+users.read+like.read+follows.read+offline.access&code_challenge=iVXBOiDvDSpbmQ9QGoQ1jG62292qWvUw-wJqx58xRpA&code_challenge_method=S256&state=300%2B2'

        state = url.split('state=')[-1].split('&')[0]
        code_challenge = url.split('code_challenge=')[-1].split('&')[0]
        client_id = url.split('client_id=')[-1].split('&')[0]

        self.session.cookies.update({'auth_token': self.auth_token, 'ct0': self.csrf})
        try:
            with self.session.get(url, timeout=15, allow_redirects=True) as response:
                with self.session.get(
                        'https://api.twitter.com/graphql/lFi3xnx0auUUnyG4YwpCNw/GetUserClaims?variables=%7B%7D',
                        timeout=15) as response:
                    pass

                self.session.headers.update({
                                           'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                                           'x-twitter-auth-type': 'OAuth2Session',
                                           'x-csrf-token': self.csrf})

                with self.session.get(
                        f'https://api.twitter.com/2/oauth2/authorize?code_challenge={code_challenge}&code_challenge_method=S256&client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.questn.com%2Fauth&response_type=code&scope=tweet.read%20users.read%20like.read%20follows.read%20offline.access&state={state}',
                        timeout=15, allow_redirects=True) as response:
                    code = response.json()['auth_code']

                    payload = {'approval': 'true', 'code': code}

                    self.session.headers.update({'content-type': 'application/x-www-form-urlencoded'})
                    with self.session.post('https://api.twitter.com/2/oauth2/authorize', data=payload,
                                      timeout=15) as response:
                        url = response.json()['redirect_uri']
                        with self.session.get(url, timeout=15) as response:

                            payload = {"code":code,"login_type":300}

                            with self.session.post('https://api.questn.com/user/auth/bind/', json=payload, timeout=15) as response:

                                if response.json()['success'] == True:

                                    print(f'Twitter connected')
                                    return True
        except:
            print(f'Twitter connection failed')
            return False

    def VerifyTwitter(self):
        # print('verifying')
        payload = {'extra': '{\"twitter_username\":\"BNBCHAIN\"}',
                   'task_id': 58144}
        try:
            with self.session.post('https://api.quest3.xyz/consumer/quest/token/task/', json=payload,
                              timeout=15) as response:
                print(response.json())
                if response.json()['result']:
                    return True
                else:
                    return False
        except Exception as e:
            print(e)
            return False

if __name__ == '__main__':

    Acc = QuestAccount(proxy='',
                       tw_csrf='',
                       tw_auth_token='',
                       address='',
                       private='',
                       dsToken=''
                       )


    res = Acc.login()
    # input()

    def ConnectSocials():
        if res['result']['user_info']['discord_uid'] == None:
            Acc.ConnectDiscord()

        if res['result']['user_info']['twitter_uid'] == None:
            Acc.ConnectTwitter()


    def Parser():
        # Acc.login()
        used = []
        Ready = []
        for page in range(1, 2):
            print(page, 'page')
            raffles = Acc.RafflesList(page)

            for raffle in raffles:

                if raffle['id'] in used:
                    continue
                used.append(raffle['id'])

                info = Acc.GetRaffleInfo(raffle['id'])
                next = True

                try:
                    for task in info['result']['task']:

                        if task['template_info']['template_id'] not in [201, 300, 200, 100300, 207, 203]:
                            next = False
                            break
                except:
                    # print('error')
                    # print(info)
                    # input()
                    next = False

                if next == False:
                    continue

                print(raffle['id'])

                # if str(raffle['id']) == '760023714001948758':
                #     pprint.pprint(info)
                #     input()

                Ready.append(info)


    def Tasks(id):
        info = Acc.GetRaffleInfo(id)
        pprint.pprint(info)
        input()
        tasks = info['result']['task']
        return tasks

    def JoinRaffle(tasks):

        Twitter = Account(auth_token=Acc.auth_token,
                          csrf=Acc.csrf,
                          proxy=Acc.defaultProxy,
                          name='1')

        for task in tasks:

            if task['template_info']['template_id'] == 200:
                TwId = Twitter.Get_User_Id(json.loads(task['extra'])['twitter_username'])
                Twitter.Follow(TwId)
                time.sleep(random.randint(100,240)/100)

            elif task['template_info']['template_id'] == 300:
                Discord(Acc.discord_token, Acc.proxy, '').JoinServer(json.loads(task['extra'])['discord_url'].split('/')[-1])

            elif task['template_info']['template_id'] == 201:
                Twitter.Retweet(json.loads(task['extra'])['tweet_url'].split('/')[-1])
                time.sleep(random.randint(100,240)/100)

            elif task['template_info']['template_id'] == 207:
                Twitter.Like(json.loads(task['extra'])['tweet_url'].split('/')[-1])
                time.sleep(random.randint(100,240)/100)

            elif task['template_info']['template_id'] == 203:

                text = json.loads(task['extra'])['tweet_url'] + '\n'
                tag_count = json.loads(task['template_info']['description'])['tag_count']

                guys = Twitter.Get_Connects()


                while text.count('@') < tag_count:
                    text+= f"@{Twitter.Get_User_Screenname(guys[text.count('@')])} "

                Twitter.Tweet(text)
                time.sleep(random.randint(100,240)/100)

        time.sleep(random.randint(4,8))

        not_ready = []

        for task in tasks:

            payload = {"task_id": task['id'], "extra": "{}"}
            print(task)

            with Acc.session.post('https://api.questn.com/consumer/quest/token/task/', json=payload,
                                  timeout=10) as response:
                print(response.text)
                if response.json()['result'] == False:
                    not_ready.append(task['id'])


        while not_ready != []:

            print('Again')

            for i in not_ready:
                payload = {"task_id": i, "extra": "{}"}

                with Acc.session.post('https://api.questn.com/consumer/quest/token/task/', json=payload,
                                      timeout=10) as response:
                    if response['result'] == True:
                        not_ready.remove(i)

        # print(Ready)

    # Parser()
    tasks = Tasks(755967005181366319)
    JoinRaffle(tasks)


