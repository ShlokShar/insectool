from utils.imports import *
import requests
from utils.params import find_parameters

xss_payloads = open("./payloads/xss.txt", 'r').read().splitlines()


def xss(url, method, url_params):
    vulnerabilities = {}
    print("[*] Starting XSS testing:")

    if not url_params:
        for payload in xss_payloads:
            if method.lower() == "post":
                req = requests.post(url, data=payload)
            else:
                req = requests.get(url + "?q=" + payload)

            if payload in req.text:
                print(Colors.FAIL + "- [!] XSS vulnerability detected with raw payload:" + Colors.ENDC)
                print("-    [%] " + payload)
                vulnerabilities["raw " + payload] = payload
            else:
                print("- [/] XSS raw payload tested: " + payload)

            headers = {
                "User-Agent": payload,
                "Referer": payload,
                "X-Forwarded-For": payload
            }
            req = requests.get(url, headers=headers)
            if payload in req.text:
                print(Colors.FAIL + "- [!] XSS reflected from header injection:" + Colors.ENDC)
                print("-    [#] Header Payload: " + payload)
                vulnerabilities[f"header {payload}"] = payload
            else:
                print("- [/] Header-based XSS tested: " + payload)
    else:
        for payload in xss_payloads:
            for parameter in url_params:
                data = {}
                data[parameter] = payload

                if method.lower() == "post":
                    req = requests.post(url, data=data)
                else:
                    req = requests.get(url, params=data)

                if payload in req.text:
                    print(Colors.FAIL + "- [!] XSS vulnerability for: " + parameter + Colors.ENDC)
                    print("-    [%] Payload: " + payload)
                    vulnerabilities[parameter] = payload
                else:
                    print("- [/] XSS tested parameter: " + parameter)

    if vulnerabilities:
        print(Colors.WARNING + "[!] XSS vulnerability for: " + url + Colors.ENDC)
    else:
        print(Colors.OKGREEN + "[+] No XSS issues found for: " + url + Colors.ENDC)

    return vulnerabilities
