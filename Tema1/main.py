import json, datetime, os, hashlib, time, sys, logging, requests, http.server, timeit
from threading import Thread
from future.standard_library import install_aliases

from http.server import BaseHTTPRequestHandler, HTTPServer

install_aliases()

from urllib.parse import urlparse, urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from urllib.error import URLError
#https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/     c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/PowerSploit.psd1
#https://               github.com/PowerShellMafia/PowerSploit/blob/c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/PowerSploit.psd1

logger = logging.getLogger("Logger")
logger.setLevel(logging.DEBUG)
 
fileHandler = logging.FileHandler("main.log", "w")
fileHandler.setLevel(logging.DEBUG)
consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s] %(name)s: %(message)s')
fileHandler.setFormatter(formatter)
consoleHandler.setFormatter(formatter)

logger.addHandler(fileHandler)
logger.addHandler(consoleHandler)
logging.root = logger

logger.debug("Started Logger!")
with open('config.json') as f:
        config_json = json.load(f)        
    
VTApiKey = config_json['VTApiKey']
hybrid_apikey = config_json['hybrid_apikey']
hybrid_secret = config_json['hybrid_secret']
hybrid_params = {"api-key": hybrid_apikey, "secret": hybrid_secret}

with open('server.json') as f:
    server_json = json.load(f)        
        
PORT_NUMBER = server_json['PORT']
HOST_NAME = server_json['HOST']
times = ""
average_time = 0
scan_results = ""


def VirusTotal(md5, sha256):
    vt_params_rescan  = {'apikey': VTApiKey, 'resource': md5}
    vt_headers_rescan = { "Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username" }                  
    hybrid_headers = { "api-key": hybrid_apikey, "Accept-Encoding": "gzip, deflate", "User-Agent" : "Falcon Sandbox" }
    # rescan = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan',  params = vt_params_rescan)
    responsed = False
    t1 = 10                                            
    while not responsed: 
        try:
            rescan = requests.get('https://www.virustotal.com/vtapi/v2/file/report',  params = vt_params_rescan)
            r = requests.get('https://www.hybrid-analysis.com/api/v2/overview/{0}'.format(sha256), params=hybrid_params, headers = hybrid_headers)
            hybrid_response = r.json()
            
            json_rescan = rescan.json()    
            strout = '***Virus Total: md5: {0}, score: {1}/{2}'.format(md5, json_rescan['positives'], json_rescan['total'])
            print(strout)
            global scan_results 
            scan_results += ("<p>" + strout + "</p>")
            responsed = True
            if 'message' in hybrid_response and hybrid_response['message'] == 'Not Found':
                strout = "***Hybrid: File Not Found"
                scan_results += ("<p>" + strout + "</p>")
                print(strout) 
            else:
                strout = '***Hybrid Analysis:  threat_score: {0}, verdict: {1}, tags: {2}'.format(hybrid_response['threat_score'], hybrid_response['verdict'], hybrid_response['tags'])
                scan_results += ("<p>" + strout + "</p>")
                print(strout)
                                                                          
        except json.decoder.JSONDecodeError:
            logger.debug("Too many requests on VT. Trying after {0} seconds.".format(t1))
            time.sleep(t1)
            t1 = int(t1 * 0.8)
            if t1 == 0:
                t1 = 10 
                                           

def GitHub():

    repoSearchKeywords = ['exploit', 'invoke']

    githubRepoSearchLink = 'https://api.github.com/search/repositories?q={keyword}+language:powershell&per_page=100'

    codeSearchKeywords = ['invoke', 'payload', 'malware', 'exploit']

    githubCodeSearchLink = 'https://api.github.com/search/code?q={word}+in:file+repo:{full_name}'
 
    total_time = 0
 
    links = list()
    output = open("output.txt", 'w')
    changedFiles = open("changedFiles.txt", "w")
    newFiles = open("newFiles.txt", "w")

    repoList = list()

    db = dict()    


    if os.path.exists('db.json'):
        db = json.load(open('db.json', 'r'))

    try:
        os.mkdir('results')
    except WindowsError:
        pass

    limit = 1
    counter = 0
    waiting_rescans = []
    for keyword in repoSearchKeywords:

        url = githubRepoSearchLink.format(keyword=keyword)

        done = False

        t = 10
        while not done:
            try:
                from urllib.request import urlopen
                f = urlopen(url)
                done = True
                logger.debug("{0}\n".format(url))
            except HTTPError as e:
                logger.debug("Too many requests GitHub. Trying after {0} seconds.".format(t))
                time.sleep(t)
                t = int(t*0.8)
            except URLError as e:
                logger.debug("Connection failed. error: {0}".format(e))
                logger.debug(url)
                break
            else:
                result = json.loads(f.read())

                for repo in result['items']:

                    if counter == limit and limit != 0:
                        break
                    start =  timeit.timeit()                    

                    counter += 1

                    name = repo['full_name']

                    if name not in db:

                        db[name] = dict()
                        db[name]['keywords'] = list()
                        db[name]['files'] = dict()

                    if keyword not in db[name]['keywords']:
                        db[name]['keywords'].append(keyword)

                    for k in codeSearchKeywords:

                        url = githubCodeSearchLink.format(full_name=name, word=k)

                        logger.debug(" [!] Searching repo: {0}".format(name))
                        logger.debug("     keyword {0}\n".format(k))

                        done = False

                        t2 = 10
                        while not done:
                            try:
                                from urllib.request import urlopen
                                g =urlopen(url)
                                done = True
                                #logger.debug("\n{0}\n{1}".format(name, url))
                            except HTTPError as e:
                                logger.debug("Too many requests on Github. Trying after {0} seconds.".format(t2))
                                time.sleep(t)
                                t2 = int(t2 * 0.8)
                            except URLError as e:
                                logger.debug("Connection failed.")
                                break
                            else:
                                r = json.loads(g.read())
                                output.write(json.dumps(r, indent=4))

                                for item in r['items']:

                                    if not item['name'].endswith('.ps1'):
                                        continue

                                    if item['html_url'] in links:
                                        #logger.debug(" >>> FILE URL ALREADY CHECKED\n")
                                        continue

                                    logger.debug("{0} / {1}".format(name, item['name']))

                                    links.append(item['html_url'])

                                    path = 'results\\{0}\\{1}'.format(name.replace('/', '_'), item['name'])

                                    try:
                                        os.mkdir(os.path.join('results', name.replace('/', '_')))
                                    except WindowsError:
                                        pass

                                    url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('blob/', '')

                                    try:
                                        from urllib.request import urlopen
                                        content = urlopen(url).read()
                                    except urllib.error.URLError as e:
                                        logger.debug("Connection failed.")
                                        content = "Connection failed for url '{0}'".format(url)
                                        break

                                    size = len(content)

                                    m = hashlib.md5()
                                    m.update(content)
                                    md5 = m.hexdigest()
                                    m = hashlib.sha256()
                                    m.update(content)
                                    sha256 = m.hexdigest()                
                                    alreadyInDB = False

                                    for f in db:
                                        for fn in db[f]['files']:
                                            if db[f]['files'][fn]['md5'] == md5:

                                                if name != f or item['name'] != fn:
                                                    logger.debug(" >>> FILE ALREADY IN DB at {0}/{1}\n".format(f, fn))
                                                else:
                                                    logger.debug(" >>> FILE ALREADY IN DB\n")
                                                alreadyInDB = True

                                    if alreadyInDB:
                                        continue

                                    isNew = True

                                    if item['name'] in db[name]['files']:

                                        if db[name]['files'][item['name']]['md5'] == md5:

                                            isNew = False

                                        else:

                                            changedFiles.write("[CHANGED] {0} > {1}\n".format(name, item['name']))
                                            logger.debug(" >>> FILE CHANGED\n")

                                    else:

                                        newFiles.write("[NEW] {0} > {1}\n".format(name, item['name']))
                                        logger.debug(" >>> FILE NEW\n")
                                        db[name]['files'][item['name']] = dict()
                                        db[name]['files'][item['name']]['path'] = item['path']

                                    if isNew:

                                        db[name]['files'][item['name']]['md5'] = md5

                                        db[name]['files'][item['name']]['size'] = size

                                        db[name]['files'][item['name']]['lastTimeDownloaded'] = datetime.datetime.strftime(datetime.datetime.now(), "%d.%m.%Y %H:%M")

                                       # open(path, 'wb').write(content)
                                        VirusTotal(md5, sha256)               
                    
                    end = timeit.timeit()
                    duration = end - start
                    total_time += duration
                    global times
                    times += ('<p>' + str(duration) + '</p>')

    times += ('<p>Average time:' + str(total_time/limit) + '</p>')

    logger.debug(db)
    global_db = db
    open('db.json', 'w').write(json.dumps(db, indent=4))

                                        

'''                                        
                                        vt_params_response  = {'apikey': VTApiKey, 'resource': json_rescan['scan_id']}
                                        vt_headers_response = {
                                                        "Accept-Encoding": "gzip, deflate",
                                                        "User-Agent" : "gzip,  My Python requests library example client or username"
                                                      }

                                        waiting_rescans.append(vt_params_response)  
'''
                                        
                                                                                                        
''' for vt_params_response in waiting_rescans:

        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',  params = vt_params_response)
        json_response = response.json()
        t1 = 10  
        
        responsed = False  
        while not responsed:                                        
            try: 
                print('md5: {0}, score: {1}/{2}'.format(md5, json_response['positives'], json_response['total']))
                responsed = True
            except:
                logger.debug("Not processed. Trying after {0} seconds.".format(t1))
                time.sleep(t1)
                t1 = int(t1 * 0.8)
                if t1 == 0:
                    t1 = 10 
                                       

'''
class MyHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        paths = {
            '/db': {'status': 200},
            '/post': {'status': 200},
            '/report': {'status': 200},
            '/times': {'status': 200},
            '/bar': {'status': 302},
            '/baz': {'status': 404},
            '/qux': {'status': 500}
        }

        if self.path in paths:
            self.respond(paths[self.path])
        else:
            self.respond({'status': 500})

    def handle_http(self, status_code, path):
        self.send_response(status_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        content = "Eroare"
        if self.path == '/db' and status_code == 200:
            with open('db.json') as f:
                my_db = json.load(f)        
                content = '<html><head><title>Exploit Watcher.</title></head><body><p>Exploit Watcher:</p><pre>{0}</pre></body></html>'.format(json.dumps(my_db, indent=4))

        if self.path == '/report' and status_code == 200:
            content = '<html><head><title>Exploit Watcher.</title></head><body><p>Exploit Watcher:</p>{0}</body></html>'.format(scan_results)
        
        if self.path == '/times' and status_code == 200:
            content = '<html><head><title>Exploit Watcher.</title></head><body><p>Exploit Watcher:</p>{0}</body></html>'.format(times)
       
        if self.path == '/post' and status_code == 200:
            content = 'Working on it. Please wait'.format(times)
            thread = Thread(target = GitHub(), args = [])
            thread.start()
            thread.join()
            
            
        
        return bytes(content, 'UTF-8')

    def respond(self, opts):
        response = self.handle_http(opts['status'], self.path)
        self.wfile.write(response)



if __name__ == '__main__':
    server_class = HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
    
    print(time.asctime(), 'Server Starts - %s:%s' % (HOST_NAME, PORT_NUMBER))
    try:

        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), 'Server Stops - %s:%s' % (HOST_NAME, PORT_NUMBER))    
    exit(0)



