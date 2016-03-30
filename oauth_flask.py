from flask import Flask, session, redirect, request, make_response
import requests
from functools import wraps
import json
import sys
import logging
import random
import string

logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("OAuth - "+__name__)

class User:
	username = None
	fullname = None
	email = None
	is_admin = False
	cookie = None

class OAuth:
	oauth_provider_uri = None
	oauth_authorize_path = None
	oauth_token_path = None
	oauth_user_path = None
	oauth_revoke_path = None
	oauth_client_id = None
	oauth_client_secret = None
	client_signin_uri = None
	client_signout_uri = None
	client_callback_uri = None
	client_uri = None
	usermeta_variable_mapping = {'username': 'username', 'is_admin': 'is_admin', 'email': 'email', 'fullname': 'name'}
	
	def __init__(self, oauth_provider_uri = None, oauth_authorize_path = None, oauth_token_path = None, oauth_user_path = None, oauth_revoke_path = None, oauth_client_id = None, oauth_client_secret = None, client_signin_uri = None, client_signout_uri = None, client_callback_uri = None, client_uri = None, usermeta_variable_mapping = None):
		params = locals()
		self.__set_attrs(params)
	
	def __set_attrs(self, params):
		for key in params:
			try:
				value = params[key]
				exec("self."+key+"='"+value+"'")
			except:
				continue

	def load_defaults(self, provider = "gitlab", provider_uri = "https://gitlab.com"):
		if provider == "gitlab":
			self.oauth_provider_uri = provider_uri
			self.oauth_authorize_path = provider_uri+'/oauth/authorize'
			self.oauth_token_path = provider_uri+'/oauth/token'
			self.oauth_user_path = provider_uri+'/api/v3/user'
			self.oauth_revoke_path = provider_uri+'/oauth/revoke'
			self.usermeta_variable_mapping = {'username': 'username', 'is_admin': 'is_admin', 'fullname': 'name', 'email': 'email'}
		elif provider == "github":
			self.oauth_provider_uri = 'https://github.com'
			self.oauth_authorize_path = 'https://github.com/login/oauth/authorize'
			self.oauth_token_path = 'https://github.com/login/oauth/access_token'
			self.oauth_revoke_path = 'https://github.com/login/oauth/revoke'			
			self.oauth_user_path = 'https://api.github.com/user'
			self.usermeta_variable_mapping = {'username': 'login', 'is_admin': 'site_admin', 'fullname': 'name', 'email': 'email'}
		elif provider == "bitbucket":
			provider_uri = 'https://bitbucket.org'
			self.oauth_provider_uri = provider_uri
			self.oauth_authorize_path = provider_uri+'/site/oauth2/authorize'
			self.oauth_token_path = provider_uri+'/site/oauth2/access_token'
			self.oauth_user_path = provider_uri+'/api/1.0/oauth/authenticate'
			self.oauth_revoke_path = provider_uri+'/site/oauth2/revoke'
			self.usermeta_variable_mapping = {'username': 'login', 'is_admin': 'site_admin', 'fullname': 'name', 'email': 'email'}


		
	def authorize(self):
		try:
			access_token = request.cookies.get('access_token')
			user = self.validate_token(access_token)
		except:
			user = None
		if not user or not user.username:
			return redirect(self.oauth_authorize_path+"?client_id="+self.oauth_client_id+"&redirect_uri="+self.client_callback_uri+"&response_type=code", 301)
		else:
			return redirect(self.client_uri, 301)
	

	def validate_token(self, access_token, role="all"):
		r = requests.get(self.oauth_user_path+"?access_token="+access_token, headers= {'Accept':'application/json'}, verify=True)
		r = r.json()
		logger.info("\tOAuth User Meta\n" + json.dumps(r, indent=4))
		try:
			if (role == 'admin' and r[self.usermeta_variable_mapping['is_admin']] == True) or (role == "all" and not r[self.usermeta_variable_mapping['is_admin']]):
				u = User()
				u.username = r[self.usermeta_variable_mapping['username']]
				u.is_admin = r[self.usermeta_variable_mapping['is_admin']]
				u.email = r[self.usermeta_variable_mapping['email']]
				u.fullname = r[self.usermeta_variable_mapping['fullname']]
				u.cookie = access_token
			else:
				u = None
		except:
			u = None
		return u

	def is_oauth_session(self):
		try:
			u = self.validate_token(request.cookies.get('access_token'))
		except:
			u = None
		if not u or not u.username:
			return False
		else:
			return True

	def retrieve_token(self, role='all'):
		r = requests.post(self.oauth_token_path, headers={ 'Host': self.oauth_provider_uri.replace("https://", ""), 'Accept': 'application/json' }, data={'code': request.args.get('code'), 'client_id': self.oauth_client_id, 'client_secret': self.oauth_client_secret, 'redirect_uri': self.client_callback_uri, 'grant_type': 'authorization_code'}, verify=True )
		r = r.json()
		try:
			user = self.validate_token(r['access_token'], role=role)
		except:
			user = None
		if not user or not user.username:
			# return redirect(self.oauth_authorize_path+"?client_id="+self.oauth_client_id+"&redirect_uri="+self.client_callback_uri+"&response_type=code", 301)
			return redirect(self.client_uri, 301)
		else:
			resp = make_response(redirect(self.client_signin_uri, 301))
			resp.set_cookie('access_token', r['access_token'])
			resp.set_cookie('login', user.username)
			resp.set_cookie('email', user.email)
			resp.set_cookie('fullname', user.fullname)
			resp.set_cookie('logout_uri', self.client_signout_uri)
			return resp

	def revoke_token(self):
		r = requests.post(self.oauth_revoke_path, headers={ 'Authorization': 'Bearer '+request.cookies.get('access_token') }, data={'token': request.cookies.get('access_token')})
		try:
			logger.info("\tOAuth Revoke Response\n" + json.dumps(r.json(), indent=4))
		except:
			logger.info("\tOAuth Revoke Response\n\tNo valid OAuth session to revoke")
		resp = make_response(redirect(self.client_uri, 301))
		resp.set_cookie('access_token', expires=0)
		resp.set_cookie('login', expires=0)
		resp.set_cookie('email', expires=0)
		resp.set_cookie('fullname', expires=0)
		resp.set_cookie('logout_uri', expires=0)
		return resp

	def default_routes(self, sign_in = "/sign_in", sign_out = "/sign_out", get_token = "/get_token", app = None, role='all'):
		if not app:
			logger.warning("You have to specify at least the flask app")
			sys.exit(1)
		else:
			self.client_callback_uri = self.client_uri + get_token
			self.client_signin_uri = self.client_uri + sign_in
			self.client_signout_uri = self.client_uri + sign_out
			randstring = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)) 
			# @app.route(sign_in)
			def _sign_in():
				return self.authorize()
			# @app.route(sign_out)
			@self.protect()
			def _sign_out():
				return self.revoke_token()
			# @app.route(get_token)
			def _get_token():
				return self.retrieve_token(role=role)
			app.add_url_rule(sign_in, '_sign_in'+randstring, _sign_in)
			app.add_url_rule(sign_out, '_sign_out'+randstring, _sign_out)
			app.add_url_rule(get_token, '_get_token'+randstring, _get_token)
 
	def protect(self, role="all"):
		def __protect(function):
			@wraps(function)
			def wrapper(*args, **kwargs):
				try:
					u = handler.validate_token(request.cookies.get('access_token'))
				except:
					u = User()
				if u and role == 'admin' and u.is_admin == True:
					return function(*args, **kwargs)
				elif u and role == 'all' and u.is_admin != None:
					return function(*args, **kwargs)
				else:
					return redirect(self.client_uri, 301)
			return wrapper
		return __protect

def multi_oauth(oauth_handlers, role="all"):
	def __multi_oauth(function):
		@wraps(function)
		def __wrapper(*args, **kwargs):
			for handler in oauth_handlers:
				try:
					u = handler.validate_token(request.cookies.get('access_token'))
				except:
					u = User()
				if u and role == 'admin' and u.is_admin == True:
					return function(*args, **kwargs)
				elif u and role == 'all' and u.is_admin != None:
					return function(*args, **kwargs)
				else:
					return redirect('/', 301)
		return __wrapper
	return __multi_oauth
