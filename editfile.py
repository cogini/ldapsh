#!/usr/bin/env python

# Utility functions to spawn an editor to edit a file

import os
import stat
import tempfile

class FileNotFoundError: pass

default_editor = "vi"

def edit_file (filename):
	"Spawn an editor to edit the specified file."
	if not filename:
		raise FileNotFoundError, "Could not open file (%s)" % filename

	try:
		editor = os.getenv('EDITOR')
	except KeyError:
		editor = default_editor
	if not editor:
		editor = default_editor

	command = "%s %s" % (editor, filename)
	status = os.system(command)
	if status != 0:
		if os.WIFEXITED(status):
			print "exit status", os.WEXITSTATUS(status)


if __name__ == "__main__":
	filename = tempfile.mktemp()
	print "filename:", filename

	fh = open(filename, "w")
	print >>fh, "Hello, world!"
	fh.close()

	mtime_before = os.stat(filename)[stat.ST_MTIME]
	print "mtime before:", mtime_before

	edit_file(filename)

	mtime_after = os.stat(filename)[stat.ST_MTIME]
	print "mtime after:", mtime_after


