import os
import webapp2
import jinja2
import hashlib, hmac
import random, string
import re
import urllib2
import json
from xml.dom import minidom

# MAPPING FUNCTIONALITY
GMAPS_URL = 'https://maps.googleapis.com/maps/api/staticmap?size=380x263&'
def gmaps_img(points):
	markers = '&'.join('markers=%s,%s' % (p.lat, p.lon) for p in points)
	return GMAPS_URL + markers


# SIGNUP VALIDATION FUNCTIONALITIES
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):

    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):

    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):

    return not email or EMAIL_RE.match(email)

# HASHING FUNCTIONALITIES
SECRET = 'basicblog'

def make_salt():
	return "".join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s,%s" % (h,salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	return h == make_pw_hash(name, pw, salt)

def make_secure_val(s):
    return '%s|%s' % (s, hmac.new(SECRET, s).hexdigest())

def check_secure_val(h):
	if h == make_secure_val(h.split('|')[0]):
		return h.split('|')[0]

from google.appengine.ext import db

# LOADING THE TEMPLATE INTO THE JINJA ENVIRONMENT
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# FOR REPRESENTING THE DATE OF EACH BLOG POST
def datetimeformat(value, format='%H:%M / %d-%m-%Y'):
    return value.strftime(format)

jinja_env.filters['datetimeformat'] = datetimeformat

# HELPER FUNCTION
def render_str(template, **params):
	#params['user'] = self.user
	t = jinja_env.get_template(template)
	return t.render(params)

IP_URL = 'http://ip-api.com/xml/'
def get_coords(ip):
	ip = '4.2.2.2'
	url = IP_URL + ip
	content = None
	try:
		content = urllib2.urlopen(url).read()
	except urllib2.URLError:
		return
	if content:
		# parse the XML and find the coordinates
		dom = minidom.parseString(content)
		status = dom.getElementsByTagName("status")[0].childNodes[0].nodeValue
		if status == 'success':
			lonNode = dom.getElementsByTagName('lon')[0]
			latNode = dom.getElementsByTagName('lat')[0]
			if lonNode and latNode and lonNode.childNodes[0].nodeValue and latNode.childNodes[0].nodeValue:
				lon = lonNode.childNodes[0].nodeValue
				lat = latNode.childNodes[0].nodeValue
				return db.GeoPt(lat, lon)

# GOOGLE DATASTORE DATABASE
class Entries(db.Model):
	title = db.StringProperty(required = True)
	body = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	coords = db.GeoPtProperty()

	def as_dict(self):
		d = {'title': self.title,
			 'body': self.body,
			 'created': datetimeformat(self.created)}
		return d 

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def register(cls, username, password, email = ''):
		pw_hash = make_pw_hash(username, password)
		return User(name = username, pw_hash = pw_hash, email = email)

	@classmethod
	def login(cls, name, pw):
		u = User.all().filter('name =', name).get()
		if u and valid_pw(name, pw, u.pw_hash):
			return u

# MAIN FUNCTIONS
class MainPage(webapp2.RequestHandler):
	def get(self):
		# self.response.headers['Content-Type'] = 'text/plain'
		# visits = 0
		# visit_cookie = self.request.cookies.get('visits')
		# if visit_cookie:
		# 	cookie_val = check_secure_val(visit_cookie)
		# 	if cookie_val:
		# 		visits = int(cookie_val)
		# 	visits += 1
		# self.response.write("You are here %s times" % visits)
		# new_cookie_val = make_secure_val(str(visits))
		# self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
		# self.response.write(self.request.remote_addr)
		# self.response.write(repr(get_coords(self.request.remote_addr)))
		entries = db.GqlQuery('select * from Entries order by created desc limit 10')
		
		# Prevent the running of multiple queries
		entries = list(entries)

		# find which entries have coordinates
		points = filter(None, (e.coords for e in entries))

		# for those entries, make an image url 
		img_url = None
		if points:
			img_url = gmaps_img(points)
		
		# now display the url		
		# self.response.write(repr(points))
		self.response.write(render_str('mainpage.html', entries=entries, img_url = img_url))
	
class NewPost(webapp2.RequestHandler):
	def get(self):
		self.response.write(render_str('newpost.html', error=""))

	def post(self):
		title = self.request.get('title')
		body = self.request.get('body')

		if title and body:
			e = Entries(title=title, body=body)
			# lookup user coordinates from IP
			# If user has IP, add them to Entries
			coords = get_coords(self.request.remote_addr)
			if coords:
				e.coords = coords
			length = db.GqlQuery('select * from Entries order by created desc').count()
			e.put()
			self.redirect('/newpost/' + str(length+1))
		else:
			self.response.write(render_str('newpost.html', error="Please type in a title and some content"))

class Permalink(webapp2.RequestHandler):
	def get(self, post_id):
		e = db.GqlQuery('select * from Entries order by created desc').get(read_policy=db.STRONG_CONSISTENCY)
		self.response.write(render_str('permalink.html', entry = e))

class SignUp(webapp2.RequestHandler):
	def get(self):
		self.response.write(render_str('signup.html'))

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		params = dict(username = username, email = email)

		if not valid_username(username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif password != verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.response.write(render_str('signup.html', **params))
		else:
			u = User.all().filter('name =', username).get()
			if u:
				self.response.write(render_str('signup.html', error_username = 'The user already exists'))
			else:
				u = User.register(username, password, email)
				u.put()
				cookie_val = make_secure_val(str(u.key().id()))
				self.response.headers.add_header('Set-Cookie', 'uid=%s; Path=/' % cookie_val)
				self.redirect('/welcome')

class Login(webapp2.RequestHandler):
	def get(self):
		self.response.write(render_str('login.html'))

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		if u:
			cookie_val = make_secure_val(str(u.key().id()))
			self.response.headers.add_header('Set-Cookie', 'uid=%s; Path=/' % cookie_val)
			self.redirect('/')
		else:
			self.response.write(render_str('/login.html', error = 'Invalid login'))

class Logout(webapp2.RequestHandler):
	def get(self):
		self.response.delete_cookie('uid')
		self.redirect('/')

class Welcome(webapp2.RequestHandler):
	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('uid')
		self.user = uid and User.get_by_id(int(uid))

	def get(self):
		self.response.write(render_str('welcome.html', username = self.user.name))

class MainPageJson(webapp2.RequestHandler):
	def get(self):
		entries = db.GqlQuery('select * from Entries order by created desc limit 10')
			
		# Prevent the running of multiple queries
		entries = list(entries)
		json_txt = ''
		for e in entries:
			json_txt += json.dumps(e.as_dict())
		
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		self.response.write(json_txt)

class PostJson(webapp2.RequestHandler):
	def get(self):
		

# APP HANDLERS
app = webapp2.WSGIApplication([('/', MainPage),
								('/newpost', NewPost),
								('/newpost/(\d+)', Permalink),
								('/signup', SignUp),
								('/welcome', Welcome),
								('/login', Login),
								('/logout', Logout),
								('/.json', MainPageJson),
								('/newpost/(\d+)', PostJson)
								], debug=True)