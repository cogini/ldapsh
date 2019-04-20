#!/usr/bin/env python

# Classes for parsing schema information read from the directory

import re
import sys
import exceptions

from syntaxes import syntaxes

try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO

class OCSchema:
	def __init__ (self, name, desc, super, must, may, is_structural):
		self.name = name
		self.desc = desc
		self.super = super
		self.must = must
		self.may = may
		self.is_structural = is_structural

	def __str__ (self):

		f = StringIO()

		print >>f, "name: " + self.name
		if self.desc:
			print >>f, "\tdesc:", self.desc
		if self.super:
			print >>f, "\tsuper:", self.super
		if self.must:
			print >>f, "\tmust:", self.must
		if self.may:
			print >>f, "\tmay:", self.may
		if self.is_structural:
			print >>f, "\tis_structural:", self.is_structural

		s = f.getvalue()
		f.close()
		return s
		
class ATSchema:
	def __init__ (self, name, syntax, is_human_readable, is_cert):
		self.name = name
		self.syntax = syntax
		self.is_human_readable = is_human_readable
		self.is_cert = is_cert

	def __str__ (self):

		f = StringIO()

		print >>f, "name: " + self.name
		if self.syntax:
			print >>f, "\tsyntax:", self.syntax
		if self.is_human_readable:
			print >>f, "\tis_human_readable:", self.is_human_readable
		if self.is_cert:
			print >>f, "\tis_cert:", self.is_cert

		s = f.getvalue()
		f.close()
		return s

class UnknownObjectClass(exceptions.Exception): pass

class Schema:
	def __init__ (self):
		self.ocdict = {}
		self.atdict = {}
		self.oc_re = re.compile(r"\s*\(\s+[\w.]+\s+(NAME\s+'([-;.\w]+)'\s+|NAME\s+\(\s+([-;.\w\s']+)\s+\)\s+)?(DESC\s+'([^']+)'\s+)?(OBSOLETE\s+)?(SUP\s+(\w+)\s+|SUP\s+\(\s+([\w$ ]+)\s+\)\s+)?(ABSTRACT\s+|STRUCTURAL\s+|AUXILIARY\s+)?(MUST\s+(\w+)\s+|MUST\s+\(\s+([\w$ ]+)\s+\)\s+)?(MAY\s+(\w+)\s+|MAY\s+\(\s+([\w$ ]+)\s+\)\s+)?" )
		self.at_re = re.compile(r"^\(\s+([-;.\w]+)(\{\d+\})?\s+(NAME\s+'([-;.\w]+)'\s+|NAME\s+\(\s+([-;.\w\s']+)\s+\)\s+)?(DESC\s+'([^']+)'\s+)?(OBSOLETE\s+)?(SUP\s+([-;.\w]+)+\s+)?(EQUALITY\s+([-;.\w]+)+\s+)?(ORDERING\s+([-;.\w]+)+\s+)?(SUBSTR\s+([-;.\w]+)+\s+)?(SYNTAX\s+([\d.{}]+)\s+)?(SINGLE-VALUE\s+)?(COLLECTIVE\s+)?(NO-USER-MODIFICATION\s+)?(USAGE\s+([\w]+)+\s+)?(.*)\)$")
		self.sep_re = re.compile(r" \$ ")

	def parse_oc_str (self, line):
		"""Parse an object class line from the directory."""

		mo = self.oc_re.search(line)
		groups = mo.groups()

		data = {}
		data['NAME tag'] = groups[0]
		data['NAME'] = groups[1]
		data['NAME multiple'] = groups[2]
		data['DESC tag'] = groups[3]
		data['DESC'] = groups[4]
		data['OBSOLETE'] = groups[5]
		data['SUP tag'] = groups[6]
		data['SUP'] = groups[7]
		data['SUP multiple'] = groups[8]
		data['type'] = groups[9] # ABSTRACT/STRUCTURAL/AUXILIARY
		data['MUST tag'] = groups[10]
		data['MUST'] = groups[11]
		data['MUST multiple'] = groups[12]
		data['MAY tag'] = groups[13]
		data['MAY'] = groups[14]
		data['MAY multiple'] = groups[15]

		if not groups[1] and not groups[2]:
			print "parse_oc_str: No name found for object class"
			print >>sys.stderr, line

		desc = data.get('DESC', '')

		# Super classes
		sup = []
		if data['SUP']:
			sup.append(data['SUP'])
		elif data['SUP multiple']:
			sup = self.sep_re.split(data['SUP multiple'])
	
		# Eliminate 'top' from list of super classes, as it is not useful
		supers = []
		for value in sup:
			if value != 'top':
				supers.append(value)

		# Mandatory attrs
		must = []
		if data['MUST']:
			must.append(data['MUST'])
		elif data['MUST multiple']:
			must = self.sep_re.split(data['MUST multiple'])
	
		# Optional attrs
		may = []
		if data['MAY']:
			may.append(data['MAY'])
		elif data['MAY multiple']:
			may = self.sep_re.split(data['MAY multiple'])
	
		names = []
		if data['NAME']:
			names.append(data['NAME'])
		elif data['NAME multiple']:
			namestr = data['NAME multiple']
			namestr = namestr.replace("'", '')
			names = namestr.split()
	
		is_structural = 0
		type = data['type']
		if type == "STRUCTURAL":
			is_structural = 1

		for name in names:
			oc = OCSchema(name, desc, supers, must, may, is_structural)
			self.ocdict[name] = oc

	def get_oc (self, name):
		"""Return OCSchema object for specified name or None if not defined. """
		self.ocdict.get(name, None)

	def parse_at_str (self, line):
		"""Parse attribute syntax definition from directory."""
		mo = self.at_re.search(line)
		groups = mo.groups()


		# DEBUG
		if not groups[1] and not groups[2]:
			print >>sys.stderr, "no name:", line


		data = {}
		data['OID'] = groups[0]
		data['LENGTH'] = groups[1]
		data['NAME'] = groups[3]
		data['NAME multiple'] = groups[4]
		data['DESC'] = groups[6]
		data['OBSOLETE'] = groups[7]
		data['SUP'] = groups[9] # super type
		data['EQUALITY'] = groups[11]
		data['ORDERING'] = groups[13]
		data['SUBSTR'] = groups[15]
		data['SYNTAX'] = groups[17]
		data['SINGLE-VALUE'] = groups[18]
		data['COLLECTIVE'] = groups[19]
		data['NO-USER-MODIFICATION'] = groups[20]
		data['USAGE'] = groups[22]
		data['OTHER'] = groups[23] # e.g. extensions

		#print "data:", data

		oid = data.get('OID', '')

		length = None
		if data['LENGTH']:
			try:
				length = int(data['LENGTH'])
			except ValueError:
				length = None

		names = []
		if data['NAME']:
			names.append(data['NAME'])
		elif data['NAME multiple']:
			namestr = data['NAME multiple']
			namestr = namestr.replace("'", '')
			names = namestr.split()

		#print "parse_at_str> names:", names

		desc = data.get('DESC', '')

		is_obsolete = 0
		if data['OBSOLETE']:
			is_obsolete = 1

		super = '' 
		if data['SUP']:
			 super = data['SUP']
			 #print "parse_at_str> super:", super

		equality = data.get('EQUALITY', '')
		ordering = data.get('ORDERING', '')
		substr = data.get('SUBSTR', '')

		syntax = data.get('SYNTAX', '')
		if syntax:
			syntax = re.sub(r"\{\d+\}$", '', syntax)
		else:
			if not super:
				print >>sys.stderr, "no syntax or super:", line


		single_value = 0
		if data['SINGLE-VALUE']:
			single_value = 1

		collective = 0
		if data['COLLECTIVE']:
			collective = 1

		no_user_modification = 0
		if data['NO-USER-MODIFICATION']:
			no_user_modification = 1

		usage = data.get('USAGE', '')
		other = data.get('OTHER', '')

		is_human_readable = 0
		is_cert = 0
		if not syntax:
			if super:
				if self.atdict.has_key(super):
					super_at = self.atdict[super]
					if super_at.syntax:
						syntax = super_at.syntax
		if syntax:
			if syntaxes.has_key(syntax):
				syntax_info = syntaxes[syntax]
				is_human_readable = syntax_info['is_human_readable']
				is_cert = syntax_info['is_cert']

		for name in names:
			at = ATSchema(name, syntax, is_human_readable, is_cert)
			self.atdict[name] = at

	def get_at (self, name):
		"""Return ATSchema object for specified name or None if not defined. """
		self.atdict.get(name, None)

	def get_oc_info (self, ocnames):
		"Get list of mandatory and optional attributes for list of object classes."
		must = {}
		may = {}
		supers = {}
		for name in ocnames:
			if self.ocdict.has_key(name):
				oc = self.ocdict[name]
				for s in oc.must:
					must[s] = 1
				for s in oc.may:
					may[s] = 1
				for s in oc.super:
					supers[s] = 1
				smust, smay = self.get_oc_info(supers.keys())
				for s in smust:
					must[s] = 1
				for s in smay:
					may[s] = 1
			else:
				raise UnknownObjectClass, "Unknown object class %s" % name
		return must.keys(), may.keys()

	def __str__ (self):

		f = StringIO()
	
		if self.ocdict:
			print >>f, "object class info:"
			keys = self.ocdict.keys()
			keys.sort()
			for key in keys:
				print >>f, self.ocdict[key]

		if self.atdict:
			print >>f, "attribute info:"
			keys = self.atdict.keys()
			keys.sort()
			for key in keys:
				print >>f, self.atdict[key]

		s = f.getvalue()
		f.close()
		return s

if __name__ == "__main__":
	parser = Schema()

	for line in sys.stdin.readlines():
		line = line[0:-1]
		parser.parse_oc_str(line)

#	for line in sys.stdin.readlines():
#		line = line[0:-1]
#		parser.parse_at_str(line)

	print parser


