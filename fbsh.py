import sys
import json, urllib, urllib2, cookielib, urlparse
import BeautifulSoup

FBSH_APP_ID='119364161472433'
FBSH_USER_AGENT='Mozilla/4.0'
FBSH_REDIRECT='http://localhost'

def http_req(url, data=None):
  if data is not None:
    data = urllib.urlencode(data)
  return urllib2.Request(url, headers={'User-Agent' : FBSH_USER_AGENT}, data=data)

# dom is a soup object, fields is a dict. returns a Request object
def http_submit_form_req(dom, form_id, submit_name, fields):
  form = dom.findAll(id=form_id)[0]
  action_url = form['action']
  if form['method'].lower() != 'post':
    raise Exception("only for form posts for now")
  inputs = form.findAll('input')
  data = {}
  for inp in inputs:
    if inp['name'] in fields:
      data[inp['name']] = fields[inp['name']]
    elif inp['type'].lower() == 'submit':
      if inp['name'] == submit_name:
        data[inp['name']] = inp['value']
    else:
      data[inp['name']] = inp['value']
  return http_req(action_url, data)

def extract_cookie(cj, name):
  candidates = [ck for ck in cj if ck.name == name]
  numcands = len(candidates)
  if numcands == 0:
    raise Exception("No such cookie by name %s" % name)
  elif numcands > 1:
    # warn about it
    print >> sys.stderr, "Multiple candidates found for cookie %s" % name
  return candidates[0]

class CustomRedirectHandler(urllib2.HTTPRedirectHandler):

  # prefix of URIs to stop at
  stoplist = [
    'http://localhost',
  ]

  def http_error_302(self, req, fp, code, msg, headers):
    if 'location' in headers:
      newurl = headers.getheaders('location')[0]
    elif 'uri' in headers:
      newurl = headers.getheaders('uri')[0]
    else:
      return

    for stopuri in self.stoplist:
      if newurl.find(stopuri) == 0:
        # match found
        return newurl

    # no match found
    return urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)

class BadEmailAndPass(Exception): pass

def do_login(email, passwd):
  cj = cookielib.CookieJar()
  opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj), CustomRedirectHandler())

  # Bootstrap cj by visiting homepage
  opener.open(http_req('https://www.facebook.com'))
  lsdValue = extract_cookie(cj, 'lsd').value

  req = opener.open(http_req('https://www.facebook.com/login.php?login_attempt=1', 
                            data={'lsd' : lsdValue,
                                  'email' : email,
                                  'pass' : passwd}))

  # Now, make a machine entry
  if req.geturl() != 'https://www.facebook.com/loginnotify/setup_machine.php':
    raise BadEmailAndPass()

  assert req.geturl() == 'https://www.facebook.com/loginnotify/setup_machine.php', req.geturl()

  # first, parse for the post_form_url
  html = req.read()
  soup = BeautifulSoup.BeautifulSoup(html)
  postFormIdValue = (soup.findAll('input', {'name' : 'post_form_id'})[0])['value']

  # now, make a request
  req = opener.open(http_req('https://www.facebook.com/loginnotify/setup_machine.php',
                            data={'lsd' : lsdValue,
                                  'post_form_id' : postFormIdValue,
                                  'machinename' : 'fbsh'}))
  assert req.geturl() == 'https://www.facebook.com/home.php', req.geturl()

  # authenticate this app
  req = opener.open(http_req('https://www.facebook.com/dialog/oauth?client_id=%s&redirect_uri=%s&response_type=token&scope=publish_stream,read_stream' % (FBSH_APP_ID, FBSH_REDIRECT)))
  if not isinstance(req, basestring):
    assert req.geturl().find('https://www.facebook.com/connect/uiserver.php') == 0, req.geturl()
    # need to explicitly allow 
    req = opener.open(http_submit_form_req(BeautifulSoup.BeautifulSoup(req.read()), 'uiserver_form', 'grant_clicked', {}))

  # req is now the localhost url
  o = urlparse.urlparse(req)
  d = urlparse.parse_qs(o.fragment)
  assert 'access_token' in d
  assert 'expires_in' in d
  token = d['access_token'][0]
  exp = int(d['expires_in'][0])
  return (token, exp)

# finally authed!
def get_graph_endpoint(token, endpoint):
  req = urllib2.urlopen(http_req('https://graph.facebook.com/%s?access_token=%s' % (endpoint, token)))
  return json.loads(req.read())

def post_graph_endpoint(token, endpoint, params):
  req = urllib2.urlopen(http_req('https://graph.facebook.com/%s?access_token=%s' % (endpoint, token), params))
  return json.loads(req.read())
