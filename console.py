#!/usr/bin/env python

# check python version
import sys
if sys.version < '2.6':
  print >> sys.stderr, "ERROR: Python >= 2.6 required"
  sys.exit(1)

# check for ssl support
import httplib
if not hasattr(httplib, 'HTTPS'):
  print >> sys.stderr, "ERROR: Your python client does not support HTTPS"
  sys.exit(1)

import atexit, os, readline
import traceback, time
import getpass, re, json

import fbsh

# setup histfile
histfile=os.path.expanduser('~/.fbshhistory')
def save_history(histfile):
  readline.write_history_file(histfile)
try:
  readline.read_history_file(histfile)
except IOError:
  pass
atexit.register(save_history, histfile)

# read existing token file
ACCESS_TOKEN = None # the global access token to access the fb graph API
EXPIRES      = None
NAME         = None

tokenfile=os.path.expanduser('~/.fbshtoken')
try:
  fp        = open(tokenfile, 'r')
  contents  = fp.read()
  if len(contents) != 0:
    tokenjson = json.loads(contents)
    token     = tokenjson['access_token']
    exp       = tokenjson['expires']
    name      = tokenjson['name']
    if time.time() < exp:
      ACCESS_TOKEN = token
      EXPIRES      = exp
      NAME         = name
  fp.close()
except IOError:
  # file doesn't exist, thats ok
  pass
except ValueError:
  print >> sys.stderr, "Could not parse fbshtoken file"

class NotLoggedInException(Exception): pass

def is_logged_in():
  return ACCESS_TOKEN != None and time.time() < EXPIRES

def require_login():
  if not is_logged_in():
    raise NotLoggedInException()

def __handle__help(args):
  if len(args) >= 2:
    for cmdarg in args[1:]:
      try:
        fullcmdarg = COMMANDS[cmdarg]
        print "NAME:"
        print "   %s -- %s" % (cmdarg, fullcmdarg.desc_str)
        print "SYNOPSIS:"
        print "   >", fullcmdarg.usage_str
      except (KeyError, IndexError):
        print "Not a command:", cmdarg
  else:
    print "Available commands:"
    cmds = COMMANDS.keys()
    cmds.sort()
    for cmd in cmds:
      print "  %s%s" % (cmd.ljust(20), COMMANDS[cmd].desc_str)
    print "Run 'help <command>' to see usage details"

def __handle__login(args):

  while True:
    email  = raw_input('Email: ')
    passwd = getpass.getpass()

    try:
      (tok, exp) = fbsh.do_login(email, passwd)
      break
    except fbsh.BadEmailAndPass:
      print "Bad email and/or password"
    except Exception as excp:
      try:
        reason = "unknown error"
        reason = excp.message
        reason = excp.reason
      except AttributeError:
        pass
      print "Error logging in:", reason
      return

  assert tok != None

  ident = fbsh.get_graph_endpoint(tok, 'me')
  name  = ident['name']

  global ACCESS_TOKEN, EXPIRES, NAME
  ACCESS_TOKEN = tok
  EXPIRES      = time.time() + exp
  NAME         = name

  try:
    fp = open(tokenfile, 'w')
    fp.write(json.dumps({'access_token':ACCESS_TOKEN,'expires':EXPIRES,'name':NAME}))
    fp.close()
  except IOError as ex:
    pass

  print "Successfully logged in as", name
  assert is_logged_in()

def __handle__logout(args=[]):
  # remember if the user was logged in for cosmetic reasons
  was_logged_in = is_logged_in()

  # clear auth state regardless
  global ACCESS_TOKEN, EXPIRES, NAME
  ACCESS_TOKEN = EXPIRES = NAME = None
  try:
    fp = open(tokenfile, 'w')
    fp.close()
  except IOError:
    pass

  if was_logged_in:
    print "Successfully logged out."
  else:
    print "Not logged in."

def __handle__exit(args=[]):
  #if is_logged_in():
  #  __handle__logout()
  print "Bye!"
  raise SystemExit

__default_indent_incr = lambda indent: indent + '  '
def __render_feed_item(item, ident='', ident_incr=__default_indent_incr):

  def print_with_ident(ident, elems=[]):
    sys.stdout.write(ident)
    print ' '.join(elems)

  TYPES = set(['status', 'link', 'video', 'photo'])
  tpe = item['type']
  if tpe not in TYPES:
    print_with_ident(ident, ["Cannot render type", tpe, repr(item)])
    print
    return

  from_name = item['from']['name']
  to_names = None
  if 'to' in item:
    to_names = [i['name'] for i in item['to']['data']]

  time = item['created_time']
  msg  = item['message'] if 'message' in item else None
  link = item['link'] if 'link' in item else None

  hdr = ' '.join([from_name, 'to', 'and'.join(to_names)]) if to_names else from_name
  print_with_ident(ident, [hdr, 'on', time, '(%s)' % tpe])
  if link:
    print_with_ident(ident, ['* ' + link])
  if msg:
    print_with_ident(ident, ['* ' + msg])

  # check for comments
  if 'comments' in item:
    comments = item['comments']['data']
    print
    for comment in comments:
      cname = comment['from']['name']
      cmsg  = comment['message']
      ctime = item['created_time']
      print_with_ident(ident_incr(ident), [cname, 'on', ctime])
      print_with_ident(ident_incr(ident), ['* ' + cmsg])
      print

  print

def __handle__newsfeed(args):
  require_login()
  newsfeed = fbsh.get_graph_endpoint(ACCESS_TOKEN, 'me/home')
  newsfeed = newsfeed['data'] # ignore paging for now

  for item in newsfeed:
    __render_feed_item(item)

def __handle__post_link(args):
  require_login()
  if len(args) == 1:
    link = raw_input('Link: ')
    msg  = raw_input('Message (press enter for empty message): ')
  else:
    assert len(args) > 1
    link = args[1]
    msg  = ' '.join(args[2:])
  fbsh.post_graph_endpoint(ACCESS_TOKEN, 'me/feed', {'link':link,'message':msg})
  print "Successfully posted link: %s" % link

def __handle__post_message(args):
  require_login()
  if len(args) == 1:
    msg = raw_input('Message: ')
  else:
    assert len(args) > 1
    msg = ' '.join(args[1:])
  fbsh.post_graph_endpoint(ACCESS_TOKEN, 'me/feed', {'message':msg})
  print "Successfully posted message: %s" % msg

def __handle__profile(args):
  require_login()
  profile = fbsh.get_graph_endpoint(ACCESS_TOKEN, 'me/feed')
  profile = profile['data']

  for item in profile:
    __render_feed_item(item)

class Cmd():
  def __init__(self, handler, usage_str, desc_str):
    self._handler = handler
    self.usage_str = usage_str
    self.desc_str = desc_str

  def __call__(self, args):
    return self._handler(args)

# 'name'         : (handler, usage, description),
COMMANDS = {
  'help'         : Cmd(__handle__help, "help [ command ]", "Show available commands"),
  'login'        : Cmd(__handle__login, "login", "Login via username/password"),
  'logout'       : Cmd(__handle__logout, "logout", "Logout and clear local state"),
  'newsfeed'     : Cmd(__handle__newsfeed, "newsfeed", "Show newsfeed"),
  'post-link'    : Cmd(__handle__post_link, "post-link", "Post a link"),
  'post-message' : Cmd(__handle__post_message, "post-message", "Post a message"),
  'profile'      : Cmd(__handle__profile, "profile", "Show profile"),
  'exit'         : Cmd(__handle__exit, "exit", "Exit fbsh"),
}

# setup completion
# http://blog.doughellmann.com/2008/11/pymotw-readline.html
class Completer(object):
  def __init__(self, options):
    self.options = sorted(options)
    return

  def complete(self, text, state):
    response = None
    if state == 0:
      # This is the first time for this text, so build a match list.
      if text:
        self.matches = [s for s in self.options if s and s.startswith(text)]
      else:
        self.matches = self.options[:]

    # Return the state'th item from the match list,
    # if we have that many.
    try:
      response = self.matches[state]
    except IndexError:
      response = None
    return response

readline.set_completer(Completer(COMMANDS.keys()).complete)
readline.parse_and_bind("tab: complete")

print "##############################################################################"
print "# Facebook Shell (fbsh.py)                                                   #"
print "# Type 'help' for a list of commands                                         #"
print "##############################################################################"

if is_logged_in():
  print "Logged in as %s" % NAME

while True:
  try:
    cmd = raw_input('> ')
    if cmd:
      tokens = re.split('\s*', cmd.strip())
      cmdtoken = tokens[0]
      try:
        COMMANDS[cmdtoken](tokens)
      except NotLoggedInException:
        print "You need to be logged in. Type 'login' to do so."
      except KeyError:
        print "Unknown command:", cmdtoken
      #except Exception as ex:
      #  print "Caught unexpected exception:", ex.value
      #  exc_type, exc_value, exc_traceback = sys.exc_info()
      #  traceback.print_exception(exc_type, exc_value, exc_traceback,
      #                            limit=10, file=sys.stdout)
  except EOFError:
    print
    __handle__exit()
  except KeyboardInterrupt:
    print
    print "Command cancelled. Type Ctrl-D or 'exit' to quit."
