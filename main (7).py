import random
import ssl
import requests
import cloudscraper
from fake_useragent import UserAgent
import capmonster_python
import time
from web3.auto import w3
from eth_account.messages import encode_defunct
import os


def _make_scraper():
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


def solve_captcha(cap_key, refferal):
    print(f'Solving captcha...')
    cap = capmonster_python.HCaptchaTask(cap_key)
    tt = cap.create_task(f'https://form.waitlistpanda.com/go/aOfkJhcpwDHpJVkzO6FB?ref={refferal}', '65a6959a-b216-4c41-92a3-15bf96f418fc')
    captcha = cap.join_task_result(tt)
    captcha = captcha["gRecaptchaResponse"]
    print(f'Captcha solved')
    return captcha


def get_list(file_name):
    list = []
    with open(file_name) as file:
        for line in file:
            list.append(line.rstrip())
    return list


def login(session, private_key, address):

    # with session.get('https://app.quest3.xyz/quest/745814372281045400', timeout=15) as response:
    #     print(response.text)

    timestamp = int(time.time())
    print(timestamp)
    message = encode_defunct(text=f'Welcome to Quest3.\nPlease sign this message to login Quest3.\n\nTimestamp: {timestamp}')
    signed_message = w3.eth.account.sign_message(message, private_key=private_key)
    signature = signed_message["signature"].hex()
    print(signature)

    session.headers.update({'Host': 'api.quest3.xyz',
                            'Content-Length': '326',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json, text/plain, */*',
                            'Origin': 'https://app.quest3.xyz',
                            'Referer': 'https://app.quest3.xyz/'
    })
    payload = {'address': address,
               'login_type': 100,
               'message': f'Welcome to Quest3.\nPlease sign this message to login Quest3.',
               'photo': random.randint(1, 12),
               'signature': signature[2:],
               'timestamp': timestamp}

    with session.post('https://api.quest3.xyz/user/login/', json=payload, timeout=15, allow_redirects=False) as response:
        # print(response.headers)
        print(response.status_code)
        print(response.json())
        if response.json()['success']:
            return response.json()['result']['access_token']
        else:
            return False


def connect_twitter(session, auth_token, csrf, id):
    url = 'https://twitter.com/i/oauth2/authorize?client_id=MW92amstNFZwWHo3dUdFQkNmY186MTpjaQ&redirect_uri=https%3A%2F%2Fapp.quest3.xyz%2Fauth&response_type=code&scope=tweet.read+users.read+like.read+follows.read+offline.access&code_challenge=iVXBOiDvDSpbmQ9QGoQ1jG62292qWvUw-wJqx58xRpA&code_challenge_method=S256&state=300%2B2'

    state = url.split('state=')[-1].split('&')[0]
    code_challenge = url.split('code_challenge=')[-1].split('&')[0]
    client_id = url.split('client_id=')[-1].split('&')[0]

    session.cookies.update({'auth_token': auth_token, 'ct0': csrf})
    try:
        with session.get(url, timeout=15, allow_redirects=True) as response:
            with session.get('https://api.twitter.com/graphql/lFi3xnx0auUUnyG4YwpCNw/GetUserClaims?variables=%7B%7D', timeout=15) as response:
                pass

            session.headers.update({'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                                    'x-twitter-auth-type': 'OAuth2Session',
                                    'x-csrf-token': csrf})

            with session.get(f'https://api.twitter.com/2/oauth2/authorize?code_challenge={code_challenge}&code_challenge_method=S256&client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.quest3.xyz%2Fauth&response_type=code&scope=tweet.read%20users.read%20like.read%20follows.read%20offline.access&state={state}', timeout=15, allow_redirects=True) as response:
                code = response.json()['auth_code']

                payload = {'approval': 'true', 'code': code}

                session.headers.update({'content-type': 'application/x-www-form-urlencoded'})
                with session.post('https://api.twitter.com/2/oauth2/authorize', data=payload, timeout=15) as response:
                    url = response.json()['redirect_uri']
                    with session.get(url, timeout=15) as response:
                        print(f'{id} - Twitter connected')
                        return True
    except:
        print(f'{id} - Twitter connection failed')
        return False


def twitter_follow(session, auth_token, csrf, user_id, id):
    authorization_token = 'AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'
    cookie = f'auth_token={auth_token}; ct0={csrf}'
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {authorization_token}',
               'x-csrf-token': csrf, 'cookie': cookie}

    try:
        with session.post(f"https://api.twitter.com/1.1/friendships/create.json?user_id={user_id}&follow=true", headers=headers, timeout=30) as response:
            if 'suspended' in response.text or 'You are unable to follow more people at this time' in response.text:
                print(f'{id} - Twitter banned')
                return False
            else:
                print(f'{id} - Follow done')
                return True
    except:
        print(f'{id} - Follow failed')
        return False


def verify_twitter(session):
    # print('verifying')
    payload = {'extra': '{\"twitter_username\":\"BNBCHAIN\"}',
               'task_id': 58144}
    try:
        with session.post('https://api.quest3.xyz/consumer/quest/token/task/', json=payload, timeout=15) as response:
            print(response.json())
            if response.json()['result']:
                return True
            else:
                return False
    except Exception as e:
        print(e)
        return False


if __name__ == '__main__':
    proxies = get_list(fr'{os.getcwd()}\Abuse\Qwest3\proxies.txt')
    addresses = get_list(fr'{os.getcwd()}\Abuse\Qwest3\addresses.txt')
    tw_auth_tokens = get_list(fr'{os.getcwd()}\Abuse\Qwest3\tw_auth_tokens.txt')
    tw_csrfs = get_list(fr'{os.getcwd()}\Abuse\Qwest3\tw_csrfs.txt')
    private_keys = get_list(fr'{os.getcwd()}\Abuse\Qwest3\private_keys.txt')
    projects = get_list(fr'{os.getcwd()}\Abuse\Qwest3\projects.txt')


    for i in range(len(proxies)):
        proxy_list = proxies[i].split(':')
        proxy = f'http://{proxy_list[2]}:{proxy_list[3]}@{proxy_list[0]}:{proxy_list[1]}'

        session = _make_scraper()
        session.proxies = {'http':proxy,
                           'https':proxy}
        session.user_agent = UserAgent().random
        adapter = requests.adapters.HTTPAdapter(max_retries=2)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        result = login(session, private_keys[i], addresses[i])
        while result == False:
            result = login(session, private_keys[i], addresses[i])

        input()

        if connect_twitter(session, tw_auth_tokens[i], tw_csrfs[i], i):
            user_id = '1052454006537314306'
            if twitter_follow(session, tw_auth_tokens[i], tw_csrfs[i], user_id, i):
                if verify_twitter(session):
                    project = random.choice(projects)
                    extra = '{' + f'\"description\":\"What is your favorite project that you\'d like us to invite for future campaigns?\",\"set_as_title\":1,\"user_answer\":\"{project}\"' + '}'
                    payload = {'extra': '{\"description\":\"What is your favorite project that you\'d like us to invite for future campaigns?\",\"set_as_title\":1,\"user_answer\":\"Helio\"}',
                               'task_id': 58145}
                    with session.post('https://api.quest3.xyz/consumer/quest/token/task/', json=payload, timeout=15) as response:
                        print(response.json())
                        if response.json()['result']:
                            print(f'{i} - Success')



        input()
