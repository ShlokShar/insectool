from utils.imports import *
from utils.params import find_parameters

generic_errors = [
    r"you have an error in your sql syntax;",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlite error",
    r"mysql_fetch_array()",
    r"mysql_num_rows()",
    r"syntax error",
    r"sql syntax",
    r"odbc",
    r"sqlstate",
]


def sql_injections(url, method, url_parameters):
    vulnerabilities = {}
    print("[*] Starting SQL injection testing:")
    for parameter in url_parameters:
        for payload in sqli_payloads:
            payload_encoded = urllib.parse.quote(payload.strip())

            if method.lower() == "get":
                req_url = f"{url}?{parameter}={payload_encoded}"
                request = requests.get(req_url)
            else:
                request = requests.post(url, data={parameter: payload})

            for error in generic_errors:
                if re.search(error, request.text.lower()):
                    print(Colors.FAIL + "- [!] SQL injection vulnerability: " + parameter + Colors.ENDC)
                    print("-    [%] Payload: " + repr(payload))
                    vulnerabilities[parameter] = payload
                    break
        if parameter not in vulnerabilities.keys():
            print("- [/] SQL injection tested parameter: " + parameter)
    if vulnerabilities:
        print(Colors.WARNING + "[!] SQLi vulnerability for: " + url + Colors.ENDC)
    else:
        print(Colors.OKGREEN + "[+] No SQLi issues found for: " + url + Colors.ENDC)

    return vulnerabilities