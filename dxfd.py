import requests
import re
import time
import json
import random
import datetime
import base64
import threading
import os
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
# from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
import requests.packages.urllib3 as urllib3

public_key_data = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+ugG5A8cZ3FqUKDwM57GM4io6JGcStivT8UdGt67PEOihLZTw3P7371+N47PrmsCpnTRzbTgcupKtUv8ImZalYk65dU8rjC/ridwhw9ffW2LBwvkEnDkkKKRi2liWIItDftJVBiWOh17o6gfbPoNrWORcAdcbpk2L+udld5kZNwIDAQAB
-----END PUBLIC KEY-----'''

requests.packages.urllib3.disable_warnings()
urllib3.util.ssl_.DEFAULT_CIPHERS = 'HIGH:!DH:!aNULL'
try:
    urllib3.contrib.pyopenssl.DEFAULT_SSL_CIPHER_LIST += 'HIGH:!DH:!aNULL'
except AttributeError:
    pass


def encrypt_para(plaintext):
    public_key = RSA.import_key(public_key_data)
    cipher = PKCS1_v1_5.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext.hex()


def ophone(t):
    key = b'34d7cb0bcdf07523'
    utf8_key = key.decode('utf-8')
    utf8_t = t.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(utf8_t, AES.block_size))
    return ciphertext.hex()


def ks(phone):
    s = requests.session()
    s.headers = {'user-agent': 'CtClient;10.4.1;Android;13;22081212C;NTQzNzgx!#!MTgwNTg1'}
    s.verify = False
    preCost = s.post('https://wapside.189.cn:9001/jt-sign/short/message/preCost',
                     json={"phone": ophone(phone), "activityCode": "shortMesssge"}).json()
    time.sleep(1)
    preCost = s.post('https://wapside.189.cn:9001/jt-sign/short/message/preCost',
                     json={"phone": ophone(phone), "activityCode": "shortMesssge"}).json()
    print(phone, '福袋:' + preCost['data']['resoultMsg'])
    tokenflag = preCost['resoultMsg']
    userCost = s.post('https://wapside.189.cn:9001/jt-sign/short/message/userCost',
                      json={"phone": ophone(phone), "activityCode": "shortMesssge", "flag": tokenflag}).json()

    if userCost["resoultCode"] == '0':
        cost = phone + ' 获得：'
        for i in userCost["data"]:
            cost += '\n\t' + i['pizeName']
        print(cost)
    receive = s.post('https://wapside.189.cn:9001/jt-sign/lottery/receive',
                     json={"para": encrypt_para(json.dumps({"phone": phone, "flag": tokenflag}))}).json()
    print(phone, '登录:' + receive['msg'])
    while True:
        addVideoCount = s.post('https://wapside.189.cn:9001/jt-sign/lottery/addVideoCount',
                               json={"para": encrypt_para(json.dumps({"phone": phone, "videoType": 202201}))}).json()
        print(phone, '视频:' + addVideoCount['msg'])
        if '用完' in addVideoCount['msg']:
            break
        time.sleep(3)
    while True:
        lotteryRevice = s.post('https://wapside.189.cn:9001/jt-sign/lottery/lotteryRevice',
                               json={"para": encrypt_para(json.dumps({"phone": phone, "flag": tokenflag}))}).json()
        content = '抽奖:' + lotteryRevice['msg']
        if lotteryRevice['code'] == '0':
            content += lotteryRevice['rname']
        print(phone, content)
        if '用完' in content or '仅限' in content or '失败' in content:
            break

        time.sleep(3)

#青龙环境变量名：PHONES，多个手机号用&区分
# 从环境变量中读取手机号字符串
phones_str = os.getenv('PHONES')
#想在本地跑将上面那一行注释掉，取消下面一行注释
#phones_str = "13800000000&13911111111&13722222222"  # 示例手机号字符串

if phones_str:
    # 使用 & 分割字符串得到手机号列表
    phones_list = phones_str.split('&')

     # 使用多线程，
    threads = []
    
    # 遍历手机号列表，使用ks函数处理每个号码
    for phone in phones_list:
        # 如果你打算使用多线程
        thread = threading.Thread(target=ks, args=(phone,))
        threads.append(thread)
        thread.start()  # 开始线程
    
    # 等待所有线程完成
    for thread in threads:
        thread.join()

