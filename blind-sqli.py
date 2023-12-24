from termcolor import colored
import argparse
import requests
import urllib.parse
import concurrent.futures
from bs4 import BeautifulSoup as bs
from fake_useragent import UserAgent
import argparse
import threading
from bs4 import Tag, NavigableString
import re
import sys
import time
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SQLiDetector:
    def __init__(self, urls, url_threads=3, proxy=None, patterns=None, output="result.txt", payload_threads=5, mode=1, verbose=1, hidden_scan=1, technique=1, params=None):
        self.url_threads = int(url_threads)
        self.payload_threads = int(payload_threads)
        self.patterns = patterns
        self.output_file_name = output
        self.urls = urls
        self.mode = mode
        self.skiped = []
        self.params = params
        
        self.buttons = ['submit', 'login', 'signin']
            
        self.technique = technique
        
        self.hidden_scan = hidden_scan
        self.verbose = verbose
        self.proxy = proxy
        self.session = requests.Session()
        self.session.verify = False
        self.ua = UserAgent()
        
        self.error403 = 0
        self.error429 = 0
        self.error404 = 0
        self.errors = 0
        
        self.warns = 0
        self.vulnsLinks = 0
        if self.proxy:
            proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
            self.session.proxies.update(proxies)
    
        self.target = self.urls
        #self.target_links = []
        #self.session = requests.Session()

    def spidy(self, url=None):
        response = self.session.get(url)
        parsed_response = bs(response.content, 'html.parser')
        elements = parsed_response.findAll('a')
        for element in elements:
            link = element.get('href')
            link = urllib.parse.urljoin(url, link)
            if '#' in link:
                link = link.split('#')[0]
            if url in link and link not in self.urls and 'logout' not in link:
                print(link)
                self.urls.append(link)
                self.spidy(link)

    def runSpider(self):
        for url in self.target:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.submit(self.spidy(url))

    def extract_forms(self, url):
        headers = {'User-Agent': self.ua.random}
        response = self.session.get(url, headers=headers).content
        parsed_response = bs(response, 'html.parser')
        forms = parsed_response.findAll('form')
        return forms

    def submit_form(self, form, url, payload):
        def find_input_fields(soup):
            input_elements = soup.find_all('input')
            #print(input_elements)
            return input_elements
                    
        headers = {'User-Agent': self.ua.random}
        postData = {}
        action = form.get('action')
        method = form.get('method')
        postUrl = urllib.parse.urljoin(url, action)
        inputs = find_input_fields(form)
        for input in inputs:
            inputName = input.get('name')
            inputValue = input.get('value')
            postData[inputName] = inputValue
            if input.get('type') == 'text':
                postData[inputName] = payload
            if self.hidden_scan == 2:
                if input.get('type') == 'hidden':
                    postData[inputName] = payload
            if self.hidden_scan == 3:
                if input.get('type') != 'hidden' and input.get('type') not in self.buttons:
                    postData[inputName] = payload
            if self.hidden_scan == 4:
                postData[inputName] = payload
        
        #print(postData)
        if method == 'GET':
            return self.session.get(postUrl, params=postData, headers=headers)
        else:
            return self.session.post(postUrl, data=postData, headers=headers)

    def detect_blind_sqli_POST(self, form, url, payload):
        headers = {
            'User-Agent': self.ua.random
        }
        
        
        
        start_time = time.time()
        raw_response = self.submit_form(form, url, payload)
        response = raw_response.content.decode()
        if self.verbose == 2 :
            print(colored(f"\t Status:{raw_response.status_code} | Method:POST| Payload:{payload} | Testing: {url}", 'green'))
        elif self.verbose == 3:
            print(colored(f"\t Status:{raw_response.status_code} | Method:POST| Payload:{payload} | Testing: {url} \n\t Form:{form}", 'green'))
        
        if raw_response.status_code == 403:
            self.error403 = self.error403 + 1
            #print("ERROR 403 BLOCKED BY Firewall.. Consider using encoded payloads")
            
        if raw_response.status_code == 429:
            self.error429 = self.error429 +1
            #print("ERROR 429 To many requests.. consider usingg lower number of threads..")
        
        if raw_response.status_code == 404:
            self.error404 = self.error404 +1
        
        if raw_response.status_code != 200 and raw_response.status_code != 403 and raw_response.status_code != 429 and raw_response.status_code != 404 :
            self.errors = self.errors +1
        
        elapsed_time = time.time() - start_time

        # Check the response time
        if elapsed_time > 15:
            print(colored(f"Vulnerable Form in: {url} \nPayload:{payload}\n{form}\n", 'red'))
            self.save_vulnerable_urls(f"vulnerable form in : {url}\nPayload: {payload}\n\n{form}\n")
            self.vulnsLinks = self.vulnsLinks + 1
        
        for pattern in self.patterns:
            matches = re.findall(pattern, response)
            if matches:
                for match in matches:
                    start_index = max(0, response.index(match) - 30)
                    end_index = min(len(response), response.index(match) + len(match) + 30)
                    matched_text = response[start_index:end_index]
                    #print(colored(f"Pattern: {pattern}, Matched Text: {matched_text}", 'yellow'))
                    self.save_vulnerable_urls(f"Found pattern : {pattern} in response\n url: {url}\n =========\n{matched_text}\n=====\n=====payload:{payload}")
                    self.warns = self.warns + 1
   
    def detect_blind_sqli_GET(self, url, payload):
        def sniper_scan(url, payload):
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
        
            for param in params:
                original_value = None  # Initialize original_value with a default value
                if self.params is not None:
                    for param_S in self.params:
                        if param_S in (param + '='):
                            original_value = params[param][0]  # Get the original value of the parameter
                            params[param] = [payload]  # Set the parameter value to the SQLi payload
                            modified_url = urlunparse(parsed_url._replace(query=urlencode(params, doseq=True)))
                            # Perform the SQLi check for the modified URL
                            check_sqli(modified_url)
                            params[param] = [original_value]  # Restore the parameter to its original value
                else:
                    original_value = params[param][0]  # Get the original value of the parameter
                    params[param] = [payload]  # Set the parameter value to the SQLi payload
                    modified_url = urlunparse(parsed_url._replace(query=urlencode(params, doseq=True)))
                    # Perform the SQLi check for the modified URL
                    check_sqli(modified_url)
                    params[param] = [original_value]  # Restore the parameter to its original value             
                                    
        def battering_ram_scan(url, payload):
            base_url, query_string = url.split("?")
            # Split the query string into individual parameter-value pairs
            params = query_string.split("&")
            
            # Create a dictionary to store the updated parameter-value pairs
            updated_params = {}
            
            # Iterate over the parameter-value pairs
            for param in params:
                key, value = param.split("=")
                if self.params != None:
                    for param_S in self.params:
                        if param_S in param+'=':
                            updated_params[key] = payload
                else:
                    updated_params[key] = payload
            
            
            # Reconstruct the updated query string
            updated_query_string = "&".join([f"{key}={value}" for key, value in updated_params.items()])
            
            # Reconstruct the updated URL
            test_url = f"{base_url}?{updated_query_string}"
            check_sqli(test_url)
                
        
        def check_sqli(test_url):
            headers = {
            'User-Agent': self.ua.random
            }
        
            start_time = time.time()
            raw_response = self.session.get(test_url, headers=headers)
            response = raw_response.content.decode()
            elapsed_time = time.time() - start_time
            if self.verbose == 2 or self.verbose == 3 :
                print(colored(f"\t Status:{raw_response.status_code} | Method:GET | Testing: {test_url}", 'green'))
    
            
            if raw_response.status_code == 403:
                self.error403 = self.error403 + 1
                #print("ERROR 403 BLOCKED BY Firewall.. Consider using encoded payloads")
                
            if raw_response.status_code == 429:
                self.error429 = self.error429 +1
                #print("ERROR 429 To many requests.. consider usingg lower number of threads..")
            
            if raw_response.status_code == 404:
                self.error404 = self.error404 +1
            
            if raw_response.status_code != 200 and raw_response.status_code != 403 and raw_response.status_code != 429 and raw_response.status_code != 404 :
                self.errors = self.errors +1
            
            
            # Check the response time
            if elapsed_time > 15:
                print(colored("Vulnerable URL: {}".format(test_url), 'red'))
                self.save_vulnerable_urls(f"vulnerable : {test_url}")
                self.vulnsLinks = self.vulnsLinks + 1
            
            for pattern in self.patterns:
                matches = re.findall(pattern, response)
                if matches:
                    for match in matches:
                        start_index = max(0, response.index(match) - 30)
                        end_index = min(len(response), response.index(match) + len(match) + 30)
                        matched_text = response[start_index:end_index]
                        #print(colored(f"Pattern: {pattern}, Matched Text: {matched_text}", 'yellow'))
                        self.save_vulnerable_urls(f"Found pattern : {pattern} in response\n url: {test_url}\n =========\n{matched_text}\n=====")
                        self.warns = self.warns + 1
        
                
        if self.technique == 1:
            #print(f"debug url2 : {url}")
            sniper_scan(url, payload)  # Call the sniper scanning function
        elif self.technique == 2:
            battering_ram_scan(url, payload)  # Call the cluster bomb scanning function
                
                    
    def scan(self, url):
        threads = []
        test = False
        c = 0
        try:
            start_time = time.time()
            response = requests.get(url, timeout=5)
            elapsed_time = time.time() - start_time

            # Check the response time
            if elapsed_time < 15:
                if response.status_code != 404:
                    for payload in payloads:
                        if self.mode == 2 or self.mode == 3:    
                            forms = self.extract_forms(url)
                            for form in forms:
                                t = threading.Thread(target=self.detect_blind_sqli_POST, args=(form, url, payload,))
                                t.start()
                                threads.append(t)
                        
                        if self.mode == 1 or self.mode == 3:
                            if '=' in url:
                                if self.params != None:
                                    for param_S in self.params:
                                        if ('&'+param_S) in url or ('?'+param_S)  in url:
                                            test = True
                                            c = c + 1
                                    if c == 0:
                                        if url not in self.skiped:
                                            print(colored(f"\t[2]Skiping {url} ", 'blue'))
                                            self.skiped.append(url)
                                else:
                                    test = True
                        if test == True:
                            #print(f"debug url: {url}")
                            t = threading.Thread(target=self.detect_blind_sqli_GET, args=(url,payload,))
                            t.start()
                            threads.append(t)
                        #print(test, c, url)
                        # Limit the number of concurrent threads
                        if len(threads) >= self.payload_threads:
                            # Wait for all threads to complete
                            for t in threads:
                                t.join()
                            threads = []
                    
                    # Wait for any remaining threads to complete
                    for t in threads:
                        t.join()  
                            
        except Exception as e :
            print(f"Connection error for URL: {url} \n Error:{e}")
            
    def run(self, urls, payloads, crawl):
        threads = []
        i = 1
        if crawl == True:
            self.runSpider()
        for url in urls:
            c = 0
            if self.mode == 1 and self.params != None:
                if '=' in url:
                    for param_S in self.params:
                        if ('&'+param_S) in url or ('?'+param_S)  in url:
                            c += 1
                        
                    if c == 0 and url not in self.skiped:    
                        #print(colored(f"\t[1]Skiping {url} ", 'blue'))
                        self.skiped.append(url)
                        i += 1
                    elif c != 0 and url not in self.skiped:
                        print(colored(f"[1][{i}/{len(urls)}][{(i/len(urls)*100):.2f}][ERROR-403:{self.error403}||ERROR-404:{self.error404}|OtherErrors:{self.errors}][PT:{self.warns}~vuln:{self.vulnsLinks}] Testing: {url}", 'green'))
                        i += 1
                        t = threading.Thread(target=self.scan, args=(url,))
                        t.start()
                        threads.append(t)                        
            if self.params == None:            
                print(colored(f"[0][{i}/{len(urls)}][{(i/len(urls)*100):.2f}][ERROR-403:{self.error403}||ERROR-404:{self.error404}|OtherErrors:{self.errors}][PT:{self.warns}~vuln:{self.vulnsLinks}] Testing: {url}", 'green'))
                i += 1
                t = threading.Thread(target=self.scan, args=(url,))
                t.start()
                threads.append(t)
                
            # Limit the number of concurrent threads
            if len(threads) >= self.url_threads:
                # Wait for all threads to complete
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for any remaining threads to complete
        for t in threads:
            t.join()  
        print(colored(f"Scan completed.. RESULT:\n-->[{i}/{len(urls)}][{(i/len(urls)*100):.2f}][ERROR-403:{self.error403}|ERROR-429:{self.error429}|ERROR-404:{self.error404}|OtherErrors:{self.errors}][PT:{self.warns}~vuln:{self.vulnsLinks}]", 'green'))
          
    def save_vulnerable_urls(self, url):
        with open(self.output_file_name, 'a') as file:
            file.write(url + '\n')  
            
def read_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.read().splitlines()
    return lines

def print_help(parser):
    print("SQLi Detector by MalikShoaib")
    print("Usage: python script.py [options]")
    print("Options:")
    for action in parser._actions:
        if len(action.option_strings) > 0:
            option_string = ', '.join(action.option_strings)
            help_text = action.help
            print(f"  {option_string}  {help_text}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SQLi Detector by MalikShoaib')
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-l', '--list', help='Path to the file containing URLs')
    
    parser.add_argument('-ut', '--urlthreads', type=int, default=3, help='Number of threads (default: 10)')
    parser.add_argument('-pt', '--payloadthreads', type=int, default=5, help='Number of threads')
    parser.add_argument('-c', '--crawl', metavar='crawl', type=str, help=' --crawl True :For crawling target urls')
    
    parser.add_argument('-p', '--payloads', default='payloads.txt', help='Path to the file containing payloads')
    parser.add_argument('-o', '--output_file', metavar='output_file', type=str, default='output.txt', help='Name of the output file')
    parser.add_argument('-ptf', '--patterns', default='patterns.txt', help='Path to the file containing patterns')
    
    parser.add_argument('-pf', '--parameters_file', help='Path to the file containing list of parameters to test only these specify parameters  (optional)')
    parser.add_argument('--proxy', help='Proxy URL (optional)')
    parser.add_argument('-m', '--mode', metavar='mode', type=int, default=1,
                        help='Scan Mode:\n\t1 - For GET method only\n\t2 - For Testing forms (POST Method) only\n\t3 - For GET & POST method')
    
    parser.add_argument('-v', '--verbose', metavar='verbose', type=int, default=1, help='Verbose: 1 - shows testing URLs | Verbose: 2 - shows each testing URL | Verbose: 3 - Shows each testing URL and form .. ')
    parser.add_argument('--hidden', help='::set value 2 for hidden&text fields and 3 for all fields except hidden fields.. and put 4 for all fields', default=1)
    parser.add_argument('-t', '--technique', metavar='technique', type=int, default=1, help='technique: 1 - for Sniper attack | technique: 2 - for battering_ram attack | ')
  
                
    args = parser.parse_args()

    urls = []
    
    urls_file = None
    if args.list:
        urls_file = args.list
    if args.url:
        urls.append(args.url)
        
    patterns_file = args.patterns
    payloads_file = args.payloads
    output_file = args.output_file
    
    param_file = args.parameters_file
    urlthreads = args.urlthreads
    payloadthreads = args.payloadthreads
    
    
    crawl = args.crawl
    if crawl:
        crawl = True
    else:
        crawl = False
    technique = args.technique
    hidden = args.hidden
    
    verbose = args.verbose
    proxy = args.proxy
    mode = args.mode

    if urls_file:
        urls = read_file(urls_file)
    patterns = read_file(patterns_file)
    payloads = read_file(payloads_file)
    if param_file:
        params   = read_file(param_file) 
    else:
        params = []
    
    print("URLs: {}".format(colored(len(urls), "cyan")))
    print("Proxy: {}".format(colored(proxy, "cyan")))
    
    print("Crawl: {}".format(colored(crawl, "cyan")))
    print("Params: {}".format(colored(len(params), "cyan")))
    
    print("Patterns: {}".format(colored(len(patterns), "cyan")))
    print("Payloads: {}".format(colored(len(payloads), "cyan")))
   
    print("Mode: {}".format(colored(mode, "cyan")))
    print("Verbose: {}".format(colored(verbose, "cyan")))
    print("Technique: {}".format(colored(technique, "cyan")))
    
    print("URLThreads: {}".format(colored(urlthreads, "cyan")))
    print("PAYLOADThreads: {}".format(colored(payloadthreads, "cyan")))
    print("Output Filename: {}".format(colored(output_file, "cyan")))
    
    if len(params) < 1:
        params = None
    time.sleep(2)
    sqli_detector = SQLiDetector(urls=urls,url_threads=urlthreads, proxy=proxy, patterns=patterns, output=output_file, payload_threads=payloadthreads, mode=mode, verbose=verbose, hidden_scan=hidden, technique=technique, params=params)
    sqli_detector.run(urls, payloads, crawl)

    
    
