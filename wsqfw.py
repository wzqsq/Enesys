import argparse
import textwrap
import warnings
from multiprocessing.dummy import Pool
import requests
import urllib3
# Enesys客户服务管理平台dwr未授权访问




def main():
    urllib3.disable_warnings()
    warnings.filterwarnings("ignore")
    parser = argparse.ArgumentParser(description="一个漏洞检测工具",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''示例：python 1111.py -u www.baidu.com / -f url.txt'''))
    parser.add_argument("-u", "--url", dest="url", help="请输入要检测的url地址")
    parser.add_argument("-f", "--file", dest="file", help="请输入要批量检测的文件")
    args = parser.parse_args()
    urls = []
    if args.url:
        if "http" not in args.url:
            args.url = f"http://{args.url}"
        check(args.url)
    elif args.file:
        with open(f"{args.file}", "r") as f:
            for i in f:
                u = i.strip()
                if "http" not in u:
                    u = f"http://{u}"
                    urls.append(u)
                else:
                    urls.append(u)
    pool = Pool(30)
    pool.map(check, urls)


def check(url):
    u = f"{url}/dwr/index.html"
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.534.106 Safari/537.36'
    }
    try:
        a = requests.get(url=u, headers=headers, verify=False,timeout=5)
        a.encoding = 'utf-8'
        html=a.text
        b = a.status_code
        if b == 200 and "yonghuWendangBean" in html:
            print('[+]存在漏洞',url)
        else:
            print('[-]不存在漏洞',url)
    except Exception as i:
        print('[x]请求发生错误',url)


if __name__ == '__main__':
    banner = '''
    $$\                                                                   
$$ |                                                                  
$$$$$$$\   $$$$$$\   $$$$$$\  $$\   $$\  $$$$$$\  $$$$$$$\   $$$$$$\  
$$  __$$\  \____$$\ $$  __$$\ $$ |  $$ |$$  __$$\ $$  __$$\ $$  __$$\ 
$$ |  $$ | $$$$$$$ |$$ /  $$ |$$ |  $$ |$$ /  $$ |$$ |  $$ |$$ /  $$ |
$$ |  $$ |$$  __$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
$$ |  $$ |\$$$$$$$ |\$$$$$$  |\$$$$$$$ |\$$$$$$  |$$ |  $$ |\$$$$$$$ |
\__|  \__| \_______| \______/  \____$$ | \______/ \__|  \__| \____$$ |
                              $$\   $$ |                    $$\   $$ |
                              \$$$$$$  |                    \$$$$$$  |
                               \______/                      \______/ 

    '''
    print(banner)
    main()

