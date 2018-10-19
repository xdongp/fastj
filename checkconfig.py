import os
import json
import urllib2

#URL = "http://adp.brocdn.com:9999/netads/api/getInterceptRules?from=527691484216954880"
URL = "http://adp.brocdn.com:9999/netads/api/getInterceptRules?from=569230400153456640"
OUT = "conf/online.ini"
CACHE = "conf/.cache"

def read_cache():
    if os.path.exists(CACHE):
        fd = open(CACHE)
        data = fd.read()
        fd.close()
        if not data:
            return 0
        return int(data)
    else:
        return 0
        

def save_cache(length):
    fd = open(CACHE, "w")
    fd.write(str(length))
    fd.flush()
    fd.close()

def reload():
    cmd = "killall -9 fastjv1"
    os.system(cmd)

def check(url):
    cmd = "curl -s -I %s|grep Length" % url
    fd = os.popen(cmd)
    data = fd.read()
    fd.close()
    length = data.split(":")[1].strip()
    if length == 0:
        print "config length is 0, return"
        return
	#length = int(length)
    old_length = read_cache()
    if int(old_length) != int(length):
        print "config changed ,load it... "
        parse(url)
        print "parse ok , reload it to fastj... "
        #reload it
        reload()
        print "load it ok, save cache"
        save_cache(length)
    else:
        print "config have not changed"
    
def parse(url):
    url_fd = urllib2.urlopen(url)
    data = url_fd.read()
    url_fd.close()
    lst = json.loads(data)
    fd = open(OUT, "w")
    for e in lst:
        fd.write("%s|%s|%s|%s|%s|%s\n" % (e['chance'], e['match'], e['platform'], e['domain'], e['path'], e['redirect']))
    fd.flush()
    fd.close()
 
if __name__ == "__main__":
    check(URL)
