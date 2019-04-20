"""
This is a wrapper on the Java JNDI interface that makes it
work like the python-ldap library from
http://python-ldap.sourceforge.net/
"""

from java.util import Hashtable
from javax.naming import *
from javax.naming.directory import *

import re

try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO

class LDAPError: pass

class Connection:
	def __init__ (self, bind_host='localhost', bind_port=389):
		self.host = bind_host
		self.port = bind_port
		self.url = "ldap://%s:%d/" % (bind_host, bind_port)
		self.ctx = None

	def simple_bind_s(self, bind_user, bind_cred):
		self.user = bind_user
		self.cred = bind_cred

		env = Hashtable()
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
		env.put(Context.PROVIDER_URL, self.url)
		env.put(Context.SECURITY_AUTHENTICATION, "simple")
		env.put(Context.SECURITY_PRINCIPAL, self.user) 
		env.put(Context.SECURITY_CREDENTIALS, self.cred)

		try:
			self.ctx = InitialDirContext(env)
		except NamingException, e:
			#e.printStackTrace()
			raise LDAPError(e)

	def get_entry (self, dn=""):
		"""Get entry data from specified DN"""
		data = {}
		try:
			attrs = self.ctx.getAttributes(dn)
			for attr in attrs.getAll():
				attr_name = attr.getID()
				attr_values = []
				for value in attr.getAll():
					attr_values.append(value)
				data[attr_name] = attr_values
		except NamingException, e:
			raise LDAPError(e)
		return [dn, data]

	def search_st (self, searchbase, scope, filter, attrs, attrs_only, timeout):
		entries = []
		try:
			cons = SearchControls()
			if scope == SCOPE_BASE:
				cons.setSearchScope(SearchControls.OBJECT_SCOPE)
			elif scope == SCOPE_SUBTREE:
				cons.setSearchScope(SearchControls.SUBTREE_SCOPE)
			elif scope == SCOPE_ONELEVEL:
				cons.setSearchScope(SearchControls.ONELEVEL_SCOPE)
			else:
				raise LDAPError("Unrecognized scope: %s" % scope)
			results = self.ctx.search(searchbase, filter, cons)
			for result in results:
				dn = result.getName()
				if dn:
					if searchbase:
						dn = dn + "," + searchbase
						entries.append(self.get_entry(dn))
		except NamingException, e:
			raise LDAPError(e)
		return entries

# package level stuff
SCOPE_BASE = 0
SCOPE_SUBTREE = 1
SCOPE_ONELEVEL = 2
NO_LIMIT = 0

def init (bind_host, bind_port):
	return Connection(bind_host, bind_port) 

def initialize (url):
	conn = Connection()
	conn.url = url
	return conn

def open (bind_host, bind_port):
	return Connection(bind_host, bind_port) 

def explode_dn (dn):
	"""Split DN into its component RDNs."""
	return re.split(r'\s*(?<!\\),\s*', dn)

def CreateLDIF (dn, data):
	"""Return LDIF string for entry data"""
	outfh = StringIO()
	print >>outfh, "dn:", entry[0] 

	# TODO: this does not do Base64 encoding
	keys = data.keys()
	keys.sort()
	for attr_name in keys:
		for value in data.get(attr_name):
			print >>outfh, "%s: %s" % (attr_name, value)

	str = outfh.getvalue()
	outfh.close()
	return str

if __name__ == "__main__":
	user = "cn=Manager,dc=Example,dc=com"
	cred = "secret"
	host = 'ldaphost'
	port = 389

	conn = init(host, port)
	conn = open(host, port)
	conn = initialize("ldap://%s:%d" % (host, port))

	conn.simple_bind_s(user, cred)
	entry = conn.get_entry("dc=Example,dc=com")
	print entry
	print CreateLDIF(entry[0], entry[1])

	print conn.search_st("dc=Example,dc=com", SCOPE_SUBTREE, "(objectClass=*)", [], 0, 0)
	print explode_dn("dc=Example,dc=com")
	print explode_dn("cn=Smith\, Joe,dc=Example, dc=com")

