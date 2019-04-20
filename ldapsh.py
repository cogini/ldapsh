#!/usr/bin/env python

# A shell-like interface to an LDAP directory
#
# This uses the python-ldap library from
# http://python-ldap.sourceforge.net/

import cmd, sys, traceback
import getopt

try:
	import readline
except:
	pass

import getpass
import tempfile
import stat
import exceptions
import os

import re

try:
	import ldap
except:
	import jndi_ldap as ldap
from ldap import LDAPError
from ldap import modlist
import ldif
from ldif import LDIFRecordList

# My modules
import schema
import parseargs
import editfile

# Utility functions
from parseargs import parse_args, split_args

def get_data_i(entry, attr_name):
	"""Get attr data from an entry, trying exact case, then lower case"""
	if entry.has_key(attr_name):
		return entry[attr_name]
	else:
		lcname = attr_name.lower()
		if entry.has_key(lcname):
			return entry[lcname]
		else:
			return []

class FormatError(exceptions.Exception): pass

def print_entry (entry, outfh):
	"""print_entry (entry)
Print a directory entry"""
	if entry[0]:
		print >>outfh, "dn:", entry[0] 
	else:
		print >>outfh, "Root entry"

	# Figure out longest key name
	max_namelen = 0
	attr_names = entry[1].keys()
	attr_names.sort()
	for attr_name in attr_names:
		length = len(attr_name)
		if length > max_namelen:
			max_namelen = length
	format = "	%%%ds - %%s" % max_namelen

	# Actually print values
	for attr_name in attr_names:
		values = entry[1].get(attr_name)
		if len(values) == 0:
			values = ['']
		print >>outfh, format % (attr_name, values[0])
		if len(values) > 1:
			for value in values[1:]:
				print >>outfh, format % ("", value)

def print_ldif (entry, outfh):
	print >>outfh, ldif.CreateLDIF(entry[0], entry[1]),
	outfh.flush()


# The main class
class ldapsh(cmd.Cmd):
	prompt = "ldapsh> "
	intro = "ldapsh: a shell-like interface to an LDAP directory"
	lastcmd = ''

	def __init__ (self):
		self.conn = None # LDAP connection object
		self.host = 'localhost'
		self.port = 389
		self.user = '' # User DN
		self.cred = '' # User password
		self.dn = '' # Current point in the directory
		self.schema = None
		self.dn_cache = {} # Mapping from index to DN
		self.dn_cache_rev = {} # Mapping from DN to index
		self.dn_index = 0 # Index of latest DN


	def get_dn (self, dn):
		"""Transform input number into DN."""
		out_dn = dn
		try:
			# Check the numeric cache
			dn_index = int(dn)
			if self.dn_cache.has_key(dn_index):
				out_dn = self.dn_cache[dn_index]
		except ValueError:
			pass
		return out_dn

	def cache_dn (self, dn):
		"""Add DN to the cache."""
		# See if it is already cached
		if self.dn_cache_rev.has_key(dn):
			return self.dn_cache_rev[dn]
		self.dn_index += 1
		self.dn_cache[self.dn_index] = dn
		self.dn_cache_rev[dn] = self.dn_index
		return self.dn_index

	def do_initialize (self, argstr):
		"""Open connection to directory using LDAP URL.
usage: initialize [ldapurl]
default is "ldap://localhost:389/"
"""
		if not argstr:
			argstr = "ldap://localhost:389/"
		try:
			new_conn = ldap.initialize(argstr)
			if self.conn:
				self.conn.unbind()
			self.conn = new_conn
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_open (self, argstr):
		"""Open connection to directory
usage: open [host] [port]
default is localhost port 389"""
		if argstr:
			args = split_args(argstr)
			print "args: ", args
			self.host = args[0]
			if len(args) > 1:
				self.port = int(args[1])
		try:
			new_conn = ldap.open(self.host, self.port)
			if self.conn:
				self.conn.unbind()
			self.conn = new_conn
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_init (self, argstr):
		"""Initialize connection parameters but don't actually connect until necessary.
usage: init [host] [port]"""
		if argstr:
			args = split_args(argstr)
			self.host = args[0]
			if len(args) > 1:
				self.port = int(args[1])
		try:
			new_conn = ldap.init(self.host, self.port)
			if self.conn:
				self.conn.unbind()
			self.conn = new_conn
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_bind (self, argstr):
		"""Bind to directory as a specific user.
usage: bind [user] [pass]
user defaults to ""
pass defaults to ""
		"""
		if not self.conn:
			self.conn = ldap.init(self.host, self.port)
		if argstr:
			args = split_args(argstr)
			self.user = self.get_dn(args[0])
			if len(args) > 1:
				self.cred = args[1]
			else:
				self.cred = getpass.getpass("password: ")
		try:
			if self.user:
				print "Binding as", self.user
			else:
				print "Binding anonymously"
			self.conn.simple_bind_s(self.user, self.cred)
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_unbind (self, argstr):
		"""Unbind from the directory."""
		if self.conn:
			try:
				self.conn.unbind()
			except LDAPError, e:
				print "error:", sys.exc_type, e
		self.conn = None


	def do_set_option (self, argstr):
		"""Set an LDAP option.
usage: set_option option value
option name does not include the OPT_ prefix.
"""
		args = split_args(argstr)
		if len(args) < 2:
			print "error: Not enough arguments"
			return
		option_str = "ldap.OPT_%s" % args[0]
		try:
			option = eval(option_str)
		except:
			print "error: invalid option name"

		value = args[1]
		try:
			self.conn.set_option(option, value)
		except LDAPError, e:
			print "error:", sys.exc_type, e


	def do_get_option (self, argstr):
		"""Get an LDAP option.
usage: get_option option 
option name does not include the OPT_ prefix.
"""
		args = split_args(argstr)
		if len(args) < 1:
			print "error: Not enough arguments"
			return
		option_str = "ldap.OPT_%s" % args[0]
		try:
			option = eval(option_str)
		except:
			print "error: invalid option name"
			return
		try:
			print self.conn.get_option(option)
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_find (self, argstr):
		"""Search the directory.
usage: find [-a attr1,attr2] [-t timeout] [-s base|subtree|onelevel] [filter] [searchbase]
-a specified a list of attributes to return. default is all (except specials).
-t specifies a timeout. default is infinite.
-s specifies search scope. default is subtree
filter defaults to "objectClass=*"
searchbase defaults to current location
"""  
		if not self.conn:
			print "Not bound to directory."
			return

		searchbase = self.dn
		filter = "objectClass=*"
		attrs = None
		timeout = -1
		scope = ldap.SCOPE_SUBTREE
		attrs_only = 0
		if argstr:
			optdict, args = parse_args(argstr, "a:t:s:")
			argc = len(args)
			if argc:
				filter = args[0]
				if argc == 2:
					searchbase = args[1]
			if optdict.has_key('-a'):
				attrstr = optdict.get('-a')
				attrs = attrstr.split(",")
			if optdict.has_key('-t'):
				try:
					timeout = int(optdict.get('-t'))
				except ValueError, e:
					print "Invalid value for timeout.", e
			if optdict.has_key('-s'):
				value = optdict.get('-s')
				if value == 'base':
					scope = ldap.SCOPE_BASE
				elif value == 'subtree':
					scope = ldap.SCOPE_SUBTREE
				elif value == 'onelevel':
					scope = ldap.SCOPE_ONELEVEL
				else:
					print "Invalid value for scope"
		try:
			result = self.conn.search_st(searchbase, scope, filter, attrs, attrs_only, timeout)
			for entry in result:
				dn = entry[0]
				dn_index = self.cache_dn(dn)
				print "%d %s" % (dn_index, dn)
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_ls (self, argstr):
		"""Display list of entries.
usage: ls [location]
location defaults to current location
""" 
		if not self.conn:
			print "Not bound to directory."
			return
		
		dn = self.dn
		if argstr:
			args = split_args(argstr)
			if len(args):
				dn = args[0]
		try:
			result = self.conn.search_s(dn, ldap.SCOPE_ONELEVEL, "objectclass=*")
			for entry in result:
				rdns = ldap.explode_dn(entry[0])
				dn_index = self.cache_dn(entry[0])
				print "%d %s" % (dn_index, rdns[0])
		except LDAPError, e:
			print "error:", sys.exc_type, e
		
	def do_cd (self, argstr):
		"""Change default location in directory."""
		if argstr:
			args = split_args(argstr)
			dn = args[0]
			if args[0] == "..":
				dn_comps = ldap.explode_dn(self.dn)
				dn = ",".join(dn_comps[1:])
				self.dn = dn
			elif args[0] == ".":
				return
			else:
				dn = self.get_dn(dn)
				self.dn = dn
			self.prompt = "ldapsh %s> " % dn

	def do_cat (self, argstr):
		"""Display contents of directory entry.
usage: cat [-a attr1,attr2] [-t timeout] [entry dn]
-a specified a list of attributes to return. default is all (except specials).
-t specifies a timeout. default is infinite.
entry dn defaults to current location
"""  
		# Defaults
		dn = self.dn
		filter = "objectClass=*"
		attrs = None
		timeout = -1
		scope = ldap.SCOPE_BASE
		attrs_only = 0

		if argstr:
			optdict, args = parse_args(argstr, "a:t:f:")
			argc = len(args)
			if argc:
				dn = args[0]
			if optdict.has_key('-a'):
				attrstr = optdict.get('-a')
				attrs = attrstr.split(",")
			if optdict.has_key('-t'):
				try: 
					timeout = int(optdict.get('-t')) 
				except ValueError, e:
					print "Invalid value for timeout. Should be integer (-1 for unlimited)", e
		dn = self.get_dn(dn)
		try:
			result = self.conn.search_st(dn, scope, filter, attrs, attrs_only, timeout)
			for entry in result:
				print_entry(entry, sys.stdout)
		except LDAPError, e:
			print "error:", sys.exc_type, e


	def do_add (self, argstr):
		"""Add an entry to the directory.
usage: add -c class1,class2 [-t timeout] dn
-c specifies a list of classes
-t specifies a timeout. default is infinite.
entry dn defaults to current location
"""  
		# Defaults
		timeout = -1

		dn = ''
		ocs = [] # list of object classes

		if not self.schema:
			self.do_load_schema("")

		if argstr:
			optdict, args = parse_args(argstr, "c:t:")
			argc = len(args)
			if argc:
				dn = args[0] + "," + self.dn
			else:
				print "No dn specified"
				return

			if optdict.has_key('-c'):
				ocstr = optdict.get('-c')
				ocs = ocstr.split(",")
			else:
				print "No object class specified"
				return

			if optdict.has_key('-t'):
				try: 
					timeout = int(optdict.get('-t')) 
				except ValueError, e:
					print "Invalid value for timeout. Should be integer (-1 for unlimited, the default)", e
		else:
			print "Missing arguments"
			return

		try:
			outdict = {} # Data to be added

			# Get data from input DN
			# TODO: encoding
			dn_comps = ldap.explode_dn(dn)
			# There may be more than one component to the RDN
			rdn_comps = ldap.explode_rdn(dn_comps[0])
			for comp in rdn_comps:
				parts = comp.split('=')
				outdict[parts[0]] = [ parts[1] ]

			outdict['objectClass'] = ocs

			try:
				# Get attributes for each object class specified
				must, may = self.schema.get_oc_info(ocs)
				# Add a * to the front of mandatory attributes
				# This identifies them and makes them sort at the front
				for attr in must:
					if outdict.has_key(attr):
						values = outdict[attr][:]
						del outdict[attr]
						outdict['*' + attr] = values
					else:
						outdict['*' + attr] = []
				for attr in may:
					if not outdict.has_key(attr):
						outdict[attr] = []
			except schema.UnknownObjectClass, e:
				print "error:", sys.exc_type, e
				return

			#print "outdict after:", outdict

			# Put data in file for editing
			filename = tempfile.mktemp()
			#print "filename:", filename

			ofh = open(filename, "w")
			keys = outdict.keys()
			keys.sort()
			print >>ofh, "dn:", dn
			for key in keys:
				values = outdict[key]
				if values:
					for value in values:
						# TODO: encoding
						print >>ofh, "%s: %s" % (key, value)
				else:
					print >>ofh, "%s: " % key
			ofh.close()

			mtime_before = os.stat(filename)[stat.ST_MTIME]
			#print "mtime before:", mtime_before

			editfile.edit_file(filename)

			mtime_after = os.stat(filename)[stat.ST_MTIME]
			#print "mtime after:", mtime_after

			# Parse file
			ifh = open(filename, "r")
			ldif_parser = LDIFRecordList(ifh)
			ldif_parser.parse()
			ifh.close()
			record = ldif_parser.all_records[0]
			#print record
			mod = modlist.addModlist(record[1])
			#print mod

			# Strip off stars
			clean_mod = []
			for pair in mod:
				name, values = pair
				if name[0] == "*":
					name = name[1:]
				clean_mod.append((name, values))

			# Add the new entry
			self.conn.add_s(dn, clean_mod)
		except LDAPError, e:
			print "error:", sys.exc_type, e


	def do_vi (self, argstr):
		"""Edit a directory entry. 
usage: vi [-c class1,class2] dn
-c specifies a list of classes
-t specifies a timeout. default is infinite.
entry dn defaults to current location
"""  
		# Defaults
		timeout = -1

		dn = ''
		ocs = [] # list of object classes

		if not self.schema:
			self.do_load_schema("")

		if argstr:
			optdict, args = parse_args(argstr, "c:t:")
			argc = len(args)
			if argc:
				dn = self.get_dn(args[0])
			else:
				print "No dn specified"
				return

			if optdict.has_key('-c'):
				ocstr = optdict.get('-c')
				ocs = ocstr.split(",")

			if optdict.has_key('-t'):
				try: 
					timeout = int(optdict.get('-t')) 
				except ValueError, e:
					print "Invalid value for timeout. Should be integer (-1 for unlimited, the default)", e
		else:
			print "Missing arguments"
			return

		# Put data in file for editing
		filename = tempfile.mktemp()
		ofh = open(filename, "w")

		scope = ldap.SCOPE_BASE
		filter = "objectClass=*"
		attrs = None
		timeout = -1
		scope = ldap.SCOPE_BASE
		attrs_only = 0
		entry = None
		try:
			result = self.conn.search_st(dn, scope, filter, attrs, attrs_only, timeout)
			if result:
				entry = result[0]
		except LDAPError, e:
			print "error:", sys.exc_type, e

		if not entry:
			print "Entry (%s) data not found" % dn
			return

		# Get list of object classes, old and new
		ocdict = {}
		for oc in ocs:
			ocdict[oc] = 1

		entry_data = entry[1]
		entry_ocs = entry_data['objectClass']

		for oc in entry_ocs:
			ocdict[oc] = 1

		ocs = ocdict.keys()

		try:
			outdict = entry_data # Data to be added

			outdict['objectClass'] = ocs

			try:
				# Get attributes for each object class specified
				must, may = self.schema.get_oc_info(ocs)
				# Add a * to the front of mandatory attributes
				# This identifies them and makes them sort at the front
				for attr in must:
					if outdict.has_key(attr):
						values = outdict[attr][:]
						del outdict[attr]
						outdict['*' + attr] = values
					else:
						outdict['*' + attr] = []
				for attr in may:
					if not outdict.has_key(attr):
						outdict[attr] = []
			except schema.UnknownObjectClass, e:
				print "error:", sys.exc_type, e
				return

			#print "outdict after:", outdict

			# Put data in file for editing
			filename = tempfile.mktemp()
			#print "filename:", filename

			ofh = open(filename, "w")
			keys = outdict.keys()
			keys.sort()
			print >>ofh, "dn:", dn
			for key in keys:
				values = outdict[key]
				if values:
					for value in values:
						# TODO: encoding
						print >>ofh, "%s: %s" % (key, value)
				else:
					print >>ofh, "%s: " % key
			ofh.close()

			mtime_before = os.stat(filename)[stat.ST_MTIME]
			#print "mtime before:", mtime_before

			editfile.edit_file(filename)

			mtime_after = os.stat(filename)[stat.ST_MTIME]
			#print "mtime after:", mtime_after
			if mtime_before == mtime_after:
				print "No changes to entry"
				return

			# Parse file
			ifh = open(filename, "r")
			ldif_parser = LDIFRecordList(ifh)
			ldif_parser.parse()
			ifh.close()
			record = ldif_parser.all_records[0]
			#print record
			mod = modlist.modifyModlist(outdict, record[1])
			#print mod

			# Strip off stars
			clean_mod = []
			for pair in mod:
				op, name, values = pair
				if name[0] == "*":
					name = name[1:]
				clean_mod.append((op, name, values))

			# Add the new entry
			self.conn.modify_s(dn, clean_mod)
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_get_ldif (self, argstr):
		"""Display contents of directory entry.
usage: get_ldif [-a attr1,attr2] [-t timeout] [-f outfile] [entry dn]
-a specified a list of attributes to return. default is all (except specials).
-t specifies a timeout. default is infinite.
entry dn defaults to current location
	"""  
		# Defaults
		dn = self.dn
		filter = "objectClass=*"
		attrs = None
		timeout = -1
		scope = ldap.SCOPE_BASE
		attrs_only = 0
		outfh = sys.stdout
		outfile = ''
	
		if argstr:
			optdict, args = parse_args(argstr, "a:t:f:")
			argc = len(args)
			if argc:
				dn = args[0]
			if optdict.has_key('-a'):
				attrstr = optdict.get('-a')
				attrs = attrstr.split(",")
			outfile = optdict.get('-f', '')
			if outfile:
				try:
					outfh = open(outfile, "w")
				except IOError, e:
					print "Could not open output file (%s)" % outfile
					print "error:", sys.exc_type, e
			if optdict.has_key('-t'):
				try: 
					timeout = int(optdict.get('-t')) 
				except ValueError, e:
					print "Invalid value for timeout.", e
			if len(args):
				dn = self.get_dn(args[0])
		try:
			result = self.conn.search_st(dn, scope, filter, attrs, attrs_only, timeout)
			for entry in result:
				print_ldif(entry, outfh)
			if outfile:
				outfh.close()

		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_naming_contexts (self, argstr):
		"""Read list of naming contexts from directory.
usage: naming_contexts 
		"""  
		if not self.conn:
			self.conn = ldap.init(self.host, self.port)
		try:
			naming_contexts = self.get_naming_contexts()
			print "Naming contexts:", naming_contexts
		except LDAPError, e:
			print "error:", sys.exc_type, e


	def do_rm (self, argstr):
		"""Read list of naming contexts from directory.
usage: rm dn 
"""  
		if not argstr:
			print "error: No DN specified."
			return

		dn = self.get_dn(argstr)
		try:
			self.conn.delete_s(dn)
			print "deleted", dn
		except LDAPError, e:
			print "error:", sys.exc_type, e


	def do_destroy_cache (self, argstr):
		"""Turns off caching and removed it from memory. 
usage: destroy_cache
"""  
		try:
			self.conn.destroy_cache()
		except LDAPError, e:
			print "error:", sys.exc_type, e


	def do_disable_cache (self, argstr):
		"""Temporarily disables use of the cache. 
New requests are not cached, and the cache is not checked when returning results. 
Cache contents are not deleted. 
usage: disable_cache
"""  
		try:
			self.conn.disable_cache()
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_flush_cache (self, argstr):
		"""Deletes the cache's contents, but does not affect it in any other way. 
usage: flush_cache
"""  
		try:
			self.conn.flush_cache()
		except LDAPError, e:
			print "error:", sys.exc_type, e


	def do_enable_cache (self, argstr):
		"""Deletes the cache's contents, but does not affect it in any other way. 
usage: enable_cache [timeout] [maxmem]
default is NO_LIMIT for both. Value should be an integer or NO_LIMIT.
"""  
		timeout = ldap.NO_LIMIT
		maxmem = ldap.NO_LIMIT
		if argstr:
			args = split_args(argstr)
			if len(args) > 0:
				if args[0] == "NO_LIMIT":
					timeout = ldap.NO_LIMIT
				else:
					try:
						timeout = int(args[0])
					except:
						print "error: invalid timeout format. Should be integer."
			if len(args) > 1:
				if args[1] == "NO_LIMIT":
					maxmem = ldap.NO_LIMIT
				else:
					try:
						maxmem = int(args[1])
					except:
						print "error: invalid maxmem format. Should be integer."
		try:
			self.conn.enable_cache(timeout, maxmem)
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_uncache_entry (self, argstr):
		"""Removes all cached entries that make reference to dn. 
This should be used, for example, after doing a modify() involving dn. 
usage: uncache_entry dn
"""  
		if argstr:
			dn = argstr
		else:
			print "error: No dn specified"

		try:
			self.conn.uncache_entry(dn)
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def get_naming_contexts (self):
		"""Get list of naming contexts."""  

		naming_contexts = [""]
		if self.conn:
			# Get subschemaSubentry location from root entry
			attrs = ['namingContexts', 'namingcontexts']
			try:
				result = self.conn.search_s("", ldap.SCOPE_BASE, "objectClass=*", attrs)
				if len(result):
					values = result[0][1]
					naming_contexts = get_data_i(values, "namingContexts")
					# Fix for wierdness with Notes directory
					if (naming_contexts[0] == "\x00"):
						naming_contexts[0] = ""
			except LDAPError, e:
				print "error:", sys.exc_type, e

		return naming_contexts

	def do_print_schema (self, argstr):
		"""Print raw schema info from directory.
usage: print_schema [-f outfile]
"""  

		outfile = ''
		if argstr:
			optdict, args = parse_args(argstr, "f:")
			outfile = optdict.get('-f', '')

		# Get subschemaSubentry location from root entry
		attrs = ['subschemaSubentry', 'subschemasubentry']
		try:
			result = self.conn.search_s("", ldap.SCOPE_BASE, "objectClass=*", attrs)
			if len(result):
				values = result[0][1]
				subentry_dns = get_data_i(values, 'subschemaSubentry')
				subentry_dn = subentry_dns[0]
			else:
				print "Root DSE not found"
				return
		except LDAPError, e:
			print "error:", sys.exc_type, e

		# Get schema data
		filter = "objectClass=*"
		attrs = ['attributeTypes', 'objectClasses', 'syntaxes', 'attributetypes', 'objectclasses']
		timeout = -1
		scope = ldap.SCOPE_BASE
		attrs_only = 0

		outfh = sys.stdout
		if outfile:
			try:
				outfh = open(outfile, "w")
			except IOError, e:
				print "Could not open output file (%s)" % outfile
				print "error:", sys.exc_type, e

		try:
			result = self.conn.search_st(subentry_dn, scope, filter, attrs, attrs_only, timeout)
			for entry in result:
				print_entry(entry, outfh)
			if outfile:
				outfh.close()
		except LDAPError, e:
			print "error:", sys.exc_type, e


	def do_load_schema (self, argstr):
		"""Load schema info from directory.
usage: load_schema 
"""  
		# Get subschemaSubentry location from root entry
		attrs = ['subschemaSubentry', 'subschemasubentry']
		try:
			result = self.conn.search_s("", ldap.SCOPE_BASE, "objectClass=*", attrs)
			if len(result):
				values = result[0][1]
				if values.has_key('subschemaSubentry'):
					subentry_dn = values['subschemaSubentry'][0]
				elif values.has_key('subschemasubentry'):
					subentry_dn = values['subschemasubentry'][0]
			else:
				print "Root DSE not found"
				return
		except LDAPError, e:
			print "error:", sys.exc_type, e

		# Get schema data
		filter = "objectClass=*"
		attrs = ['attributeTypes', 'objectClasses', 'syntaxes', 'attributetypes', 'objectclasses']
		timeout = -1
		scope = ldap.SCOPE_BASE
		attrs_only = 0

		try:
			so = schema.Schema()
			result = self.conn.search_st(subentry_dn, scope, filter, attrs, attrs_only, timeout)
			for entry in result:
				data = entry[1]
				if data.has_key('attributeTypes'):
					for str in data['attributeTypes']:
						so.parse_at_str(str)
				if data.has_key('objectClasses'):
					for str in data['objectClasses']:
						so.parse_oc_str(str)
			self.schema = so
			#print self.schema
		except LDAPError, e:
			print "error:", sys.exc_type, e

	def do_dump_schema(self, argstr):
		outfile = ''
		if argstr:
			optdict, args = parse_args(argstr, "f:")
			outfile = optdict.get('-f', '')

		outfh = sys.stdout
		if outfile:
			try:
				outfh = open(outfile, "w")
			except IOError, e:
				print "Could not open output file (%s)" % outfile
				print "error:", sys.exc_type, e

		if not self.schema:
			self.do_load_schema("")

		print >>outfh, self.schema
		if outfile:
			outfh.close()

	def do_describe_oc(self, argstr):
		"""Print schema information for specified object class.
usage: describe_oc ocname
"""
		if argstr:
			optdict, args = parse_args(argstr, "")

		if not args:
			print "No attribute class name specified."

		if not self.schema:
			self.do_load_schema("")

		print self.schema.get_oc(args[0])

	def do_describe_at(self, argstr):
		"""Print schema information for specified attribute.
usage: describe_at atname
"""
		if argstr:
			optdict, args = parse_args(argstr, "")

		if not args:
			print "No attribute class name specified."

		if not self.schema:
			self.do_load_schema("")

		print self.schema.get_at(args[0])

	def do_explode_dn (self, argstr):
		"""Explode DN.
usage: explode_dn dn
"""
		if not argstr:
			print "error: No DN specified"

		print ldap.explode_dn(argstr)

	def do_pwd (self, argstr):
		"""Print current location in directory."""
		print self.dn

	def default (self, argstr):
		print "Unrecognized command: " + argstr

	# Do nothing on empty line
	def emptyline (self):
		pass

	# Exit interpreter
	def do_exit (self, arg):
		if self.conn:
			self.conn.unbind()
		return -1

	def do_ZZ (self, arg):
		if self.conn:
			self.conn.unbind()
		return -1

	# Exit interpreter
	def do_EOF (self, arg):
		if self.conn:
			self.conn.unbind()
		return -1

	def do_set (self, arg):
		print "host: ", self.host
		print "port: ", self.port
		print "user: ", self.user
		#print "cred: ", self.cred


if __name__ == "__main__":
	usage = "usage: %s [-h host] [-p port] [-u user] [-c password] [-b starting_dn]" 
	try:
		opts, pargs = getopt.getopt(sys.argv[1:], "h:p:u:c:b:?")
	except getopt.GetoptError, e:
		print e
		print usage % sys.argv[0]
		sys.exit()
	optdict = {}
	for pair in opts:
		optdict[pair[0]] = pair[1]

	if optdict.has_key('-?'):
		print usage % sys.argv[0]
		sys.exit()

	interp = ldapsh()

	# Connect to directory using command line args
	interp.host = optdict.get('-h', '')
	interp.port = int(optdict.get('-p', 389))
	user = optdict.get('-u', '')
	interp.cred = optdict.get('-c', '')
	if optdict.has_key('-u'):
		interp.user = optdict.get('-u')
		if not optdict.has_key('-c'):
			interp.cred = getpass.getpass("Password: ")
		interp.do_bind("")

	# Set initial location in directory
	if optdict.has_key('-b'):
		# Use command line arg
		interp.do_cd(optdict.get('-b'))
	else:
		# Set initial point to naming context from directory
		# Use the first naming context
		# Another option would be to use the shortest one
		naming_contexts = interp.get_naming_contexts()
		interp.do_cd(naming_contexts[0])

	interp.cmdloop()

