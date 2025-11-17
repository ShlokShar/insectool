import json
from modules.xss import xss
from modules.sqli import sql_injections
from modules.cookies import cookies
from utils.params import find_parameters
from utils.constants import head, icon

def scan_vulnerabilities(url):
    params = find_parameters(url)
    vulnerabilities = []

    for method in ["get"]:
        vulnerabilities.append(xss(url, method, params))
        vulnerabilities.append(sql_injections(url, method, params))

    vulnerabilities.append(cookies(url))
    return vulnerabilities


def main():
    print(head)
    print(icon)
    url = input("URL: >> ").strip()
    if not url:
        print("Please provide a valid URL.")
        return
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        vulns = scan_vulnerabilities(url)
        with open("report.json", "w") as f:
            json.dump(vulns, f, indent=4)
        print("Vulnerabilities written to: report.json")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
