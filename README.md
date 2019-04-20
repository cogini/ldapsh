# ldapsh

This is a CLI written in Python which allows you to manage an LDAP directory.

It was written around 2003 and is only being published now, so it probably requires some updating.
It was used to interact with an Active Directory system from a Sun Solaris server.

The most interesting part is probably the editing feature, which takes the LDAP entry, converts it
to text, then loads it up in an editor. It identifies changes, if any, and writes them back to the directory.

It relies on the [python-ldap](https://github.com/python-ldap/python-ldap) library to do its work.
It also has support for Java JNDI, allowing it to be used from Jython.
