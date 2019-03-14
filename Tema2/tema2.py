import os
import pymongo
import json
import re
from bson import BSON
from bson import json_util
from bson.json_util import dumps
from collections import OrderedDict

code200Header = 'HTTP/1.0 200 OK\nContent-Type: application/vnd.api+json\n\n'
code201Header = 'HTTP/1.0 201 Created\nContent-Type: application/vnd.api+json\n\n'
code204Header = 'HTTP/1.0 204 No Content\nContent-Type: application/vnd.api+json\n\n'
code400Header = 'HTTP/1.0 400 Bad Request\nContent-Type: application/vnd.api+json\n\n'
code404Header = 'HTTP/1.0 404 Not Found\nContent-Type: application/vnd.api+json\n\n'
code409Header = 'HTTP/1.0 409 Conflict\nContent-Type: application/vnd.api+json\n\n'
code415Header = 'HTTP/1.0 415 Unsupported Media Type\nContent-Type: application/vnd.api+json\n\n'
code422Header = 'HTTP/1.0 422 Unprocessable Entity\nContent-Type: application/vnd.api+json\n\n'
code500Header = 'HTTP/1.0 500 Internal Server Error\nContent-Type: application/vnd.api+json\n\n'

from http.server import BaseHTTPRequestHandler, HTTPServer


class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/repos' or self.path == '/repos/':
            result = tema2DB['paths'].find()                     
            self.wfile.write(bytearray((code200Header) + dumps(result), 'utf-8'))
        elif self.path[:12] == '/repos/repo/':  
            repo = self.path.split('/', 3)[3]
            result = tema2DB['paths'].find({'repo': repo}, projection={'repo': 1, 'infos': 1, '_id': 0})
            if result.count() == 0:
                self.wfile.write(bytearray((code422Header) + "nu am putut procesa repo-ul: " + repo, 'utf-8'))            
            else:
                self.wfile.write(bytearray((code200Header) + dumps(result), 'utf-8'))
        elif self.path[:11] == '/repos/md5/':  
            md5 = self.path.split('/', 3)[3]
            if not re.findall(r"([a-fA-F\d]{32})", md5):
                self.wfile.write(bytearray((code400Header) + md5 + ' nu este un md5 valid', 'utf-8'))                                
            else:
                result = tema2DB['paths'].find({'infos.files.fileinfo.md5' : md5}, projection={'repo': 1, 'infos': 1, '_id': 0})                
                print(result.count())
                if result.count() == 0:
                    self.wfile.write(bytearray((code204Header), 'utf-8')) 
                else:
                    
                    self.wfile.write(bytearray((code200Header) + dumps(result), 'utf-8'))
            
        else:
            self.wfile.write(bytearray((code404Header + "[GET]mare greseala"), 'utf-8'))
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        try: 
            posted_data = json.loads(self.rfile.read(content_length))
        except:
            self.wfile.write(bytearray((code415Header + "datele furnizate nu sunt  inf format JSON"), 'utf-8'))
            return            
#        print(posted_data)
        result = tema2DB['paths'].find({'repo': posted_data['repo']}, projection={'repo': 1, 'infos': 1, '_id': 0})
        if self.path != '/repos/repo/' and self.path != '/repos/repo':
                self.wfile.write(bytearray((code404Header + "[POST]mare greseala"), 'utf-8'))
                return
        found = 0
        for elem in result:
            if elem == posted_data:
                found = 1

        if found == 1:
            self.wfile.write(bytearray((code409Header) + "Exista deja", 'utf-8'))
        else:
            tema2DB['paths'].insert_one(posted_data)
            self.wfile.write(bytearray((code201Header) + "Am adaugat cu succes in DB", 'utf-8'))
            
#        print(found)    

    def do_PUT(self):
        content_length = int(self.headers['Content-Length'])
        try: 
            posted_data = json.loads(self.rfile.read(content_length))
        except:
            self.wfile.write(bytearray((code415Header + "datele furnizate nu sunt  inf format JSON"), 'utf-8'))
            return
        if self.path != '/repos/repo/' and self.path != '/repos/repo':
            self.wfile.write(bytearray((code404Header + "[PUT]mare greseala"), 'utf-8'))
            return

        result = tema2DB['paths'].find({'repo': posted_data['repo']}, projection={'repo': 1, 'infos': 1, '_id': 0})
        found = 0
        for elem in result:
            tema2DB['paths'].replace_one(elem, posted_data, True)
            found = 1    

        if found == 1:
            self.wfile.write(bytearray((code200Header) + "Am facut replace", 'utf-8'))
        else:
            tema2DB['paths'].insert_one(posted_data)
            self.wfile.write(bytearray((code201Header) + "Am adaugat cu succes in DB un element nou", 'utf-8'))
    def do_DELETE(self):
        content_length = int(self.headers['Content-Length'])
        try: 
            posted_data = json.loads(self.rfile.read(content_length))
        except:
            self.wfile.write(bytearray((code415Header + "datele furnizate nu sunt  inf format JSON"), 'utf-8'))
            return         
        if self.path != '/repos/repo/' and self.path != '/repos/repo':
                self.wfile.write(bytearray((code404Header + "[DELETE]mare greseala"), 'utf-8'))
                return
        result = tema2DB['paths'].find({'repo': posted_data['repo']}, projection={'repo': 1, 'infos': 1, '_id': 0})
        found = 0
        for elem in result:
            if elem == posted_data:
                found = 1
                tema2DB['paths'].delete_one(elem)

        if found == 1:
            self.wfile.write(bytearray((code200Header) + "Sergerea efectuata cu succes", 'utf-8'))
        else:
            self.wfile.write(bytearray((code404Header) + "nu am gasit repo-ul dat", 'utf-8'))
            
   
        
def initDB():
    
    global tema2DB
    myclient = pymongo.MongoClient("mongodb+srv://abucevschi:parola@cluster0-1co8t.mongodb.net/test?retryWrites=true")
    tema2DB = myclient["tema2DB"]
    

def main():
    httpd = HTTPServer(('localhost', 8080), MyHandler)
    httpd.serve_forever()
    


def populateDB():   
    if os.path.exists('db.json'):
        db = json.load(open('db.json', 'r'))
    
    for key, value in db.items():
        for filename, infos in value['files'].items():
            print(value)
            tema2DB['paths'].insert({"repo": key, "infos": {'keywords': value['keywords'], 'files': {'filename': filename, 'fileinfo': infos}}}, check_keys=False)
    print("done populating")
    
if __name__ == '__main__':
    initDB()
#    populateDB()    
    main()
