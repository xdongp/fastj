import json
import urllib2

URL = "http://adp.brocdn.com:9999/netads/api/getInterceptRules?from=527691484216954880"
OUT = "out.ini"

def parse(url):
    url_fd = urllib2.urlopen(url)
    data = url_fd.read()
    url_fd.close()
    lst = json.loads(data)
    for e in lst:
        print "%s|%s|%s|%s|%s|%s" % (e['chance'], e['match'], e['platform'], e['domain'], e['path'], e['redirect'])
 
if __name__ == "__main__":
    parse(URL)
