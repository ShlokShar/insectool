from utils.imports import *
import base64
import requests

generic_keys = [
    "admin", "user", "role", "email", "token",
    "auth", "session", "username", "password",
]


def cookies(url):
    session = requests.Session()
    response = session.get(url, allow_redirects=True)
    vulnerabilities = {}

    print("[*] Starting Cookie testing:")
    for cookie in response.cookies:
        print(f"    [%] Value: {cookie.value}")
        print(f"    [%] Domain: {cookie.domain}")
        print(f"    [%] Path: {cookie.path}")
        print(f"    [%] Secure: {cookie.secure}")
        print(f"    [%] HttpOnly: {'HttpOnly' in cookie._rest}")
        print(f"    [%] SameSite: {cookie._rest.get('samesite', 'Missing')}")

        if not cookie.secure:
            print(Colors.WARNING + "[!] Cookie vulnerability: insecure flag" + Colors.ENDC)
            vulnerabilities["secure flag"] = False
        if 'HttpOnly' not in cookie._rest:
            print(Colors.WARNING + "[!] Cookie vulnerability: nil httponly flag" + Colors.ENDC)
            vulnerabilities["httponly"] = False
        if 'samesite' not in cookie._rest:
            print(Colors.WARNING + "[!] Cookie vulnerability: nil samesite attribute" + Colors.ENDC)
            vulnerabilities["samesite"] = False
        if len(cookie.value) < 16:
            print(Colors.WARNING + "[!] Cookie vulnerability: brute force" + Colors.ENDC)
            vulnerabilities["brute force"] = True

        try:
            decoded = base64.b64decode(cookie.value).decode('utf-8', errors='ignore')
        except Exception:
            decoded = "error in decoding"
        for keyword in generic_keys:
            if keyword.lower() in decoded.lower():
                print(Colors.FAIL + f"[!] Cookie vulnerability: b64 decodable" + Colors.ENDC)
                print("-    [%] Decoded Keyword: " + keyword.lower())
                vulnerabilities[f"decoded {keyword}"] = decoded.lower()
            if keyword.lower() in cookie.value.lower():
                print(Colors.FAIL + f"[!] Cookie vulnerability: not encoded" + Colors.ENDC)
                print("-    [%] Keyword: " + keyword.lower())
                vulnerabilities[keyword] = cookie.value.lower()
    if vulnerabilities:
        print(Colors.WARNING + "[!] Cookie vulnerability for: " + url + Colors.ENDC)
    else:
        print(Colors.OKGREEN + "[+] No Cookie issues found for: " + url + Colors.ENDC)

    return vulnerabilities
