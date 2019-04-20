# Utilities for handling command line args

import re
import getopt

def split_args (argstr):
	"""Split a string into a list of arguments like the Bourne shell 
does with its command line"""

	# Strip leading spaces
	argstr = re.sub(r'^\s+', '', argstr) 
	if not argstr:
		return [""] # nothing but whitespace

	# Check for simple empty string
	if argstr == '""':
		return ['']

	# Look for quotes and escapes
	match = re.search(r'["\'\\]', argstr)
	tokens = []
	if match:
		while 1:
			token, rest = get_token(argstr)
			tokens.append(token)
			if rest == None: break
			argstr = rest
		return tokens
	else:
		# No special stuff, just split on whitespace
		return argstr.split()

def get_token (argstr):
	"""Get a token from the front of the string. Used in argument parsing.

	Returns a tuple consisting of the token and the rest of the string, 
	or None for the last token.
	"""

	# Look for quotes
	if argstr[0] == '"' or argstr[0] == "'":
		# Quoted string
		# Find end quote
		match = re.search('[^\\\\](["\'])', argstr)
		if match:
			start_i = match.start(0)
			token = argstr[1:start_i + 1]
			token = re.sub(r'\\([\'"\\ ])', r'\1', token) # Get rid of escapes
			end_i = match.end(0)
			if end_i == len(argstr):
				# Only one token
				return token, None
			else:
				rest = argstr[end_i + 1:]
				return token, rest
		else:
			raise FormatError, "Missing closing quote"
	else:
		# No quotes, but may be escaped stuff
		# Find first non-quoted space
		space_match = re.search(r"[^\\](\s+)", argstr)
		if space_match:
			# Got a space
			token = argstr[0:space_match.start(1)]
			token = re.sub(r'\\([\'"\\ ])', r'\1', token) # Get rid of escapes
			rest = argstr[space_match.end(1):]
			if rest:
				return token, rest
			else:
				return token, None
		else:
			# Only one token
			argstr = re.sub(r'\\([\'"\\ ])', r'\1', argstr) # Get rid of escapes
			return argstr, None
	
def parse_args (argstr, spec):
	"""Parse arguments like getopt. 
argstr is a string with the args.
spec is a list of expected args.
Returns a dict with dash args and a list of other args."""

	args = split_args(argstr)
	try:
		opts, pargs = getopt.getopt(args, spec)
	except getopt.GetoptError, e:
		print e
		return {}, []
	optdict = {}
	for pair in opts:
		optdict[pair[0]] = pair[1]

	return optdict, pargs
