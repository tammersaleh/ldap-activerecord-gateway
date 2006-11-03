Using the example programs
==========================

These servers all listen on port 1389 by default, so that they don't have to
be run as root.

Example 1: trivial server using RAM hash
----------------------------------------

$ ruby rbslapd1.rb

In another window:

$ ldapadd -H ldap://127.0.0.1:1389/
dn: dc=example,dc=com
cn: Top object

dn: cn=Fred Flintstone,dc=example,dc=com
cn: Fred Flintstone
sn: Flintstone
mail: fred@bedrock.org
mail: fred.flintstone@bedrock.org

dn: cn=Wilma Flintstone,dc=example,dc=com
cn: Wilma Flintstone
mail: wilma@bedrock.org
^D

Try these queries:

$ ldapsearch -H ldap://127.0.0.1:1389/ -b "" "(objectclass=*)"
$ ldapsearch -H ldap://127.0.0.1:1389/ -b "dc=example,dc=com" -s base "(objectclass=*)"
$ ldapsearch -H ldap://127.0.0.1:1389/ -b "dc=example,dc=com" "(mail=fred*)"

If you terminate the server with Ctrl-C, its contents should be written
to disk as a YAML file.

A fairly complete set of the filter language is implemented. However, this
simple server works by simply scanning the entire database and applying the
filter to each entry, so it won't scale to large applications. No validation
of DN or attributes against any sort of schema is done.

Example 1a: with SSL
--------------------

In rbslapd1.rb, uncomment

	:ssl_key_file		=> "key.pem",
	:ssl_cert_file		=> "cert.pem",
	:ssl_on_connect		=> true,

and run mkcert.rb. Since this is a self-signed certificate, you'll have to
turn off certificate verification in the client too. For example:

    $ env LDAPTLS_REQCERT="allow" ldapsearch -H ldaps://127.0.0.1:1389/

Making your own CA and installing its certificate in the client, or
generating a Certificate Signing Request and sending it to a known CA, is
beyond the scope of this documentation.

Example 2: simple LDAP to SQL mapping
-------------------------------------

You will need to set up a MySQL database with a table conforming to the
schema given within the code. Once done, LDAP gives a read-only view of the
database with only the filter "(uid=<foo>)" supported.

Example 3: preforking server and schema
---------------------------------------

This functions in the same way as rbslapd1.rb. However, since each query is
answered in a separate process, the YAML file on disk is used as the master
repository. Update operations re-write this file each time.

Also, the schema is read from file 'core.schema'. Attempting to insert the
above entries will fail, due to schema violations. Insert a valid entry,
e.g.

dn: cn=Fred Flintstone,dc=example,dc=com
objectClass: organizationalPerson
cn: Fred Flintstone
sn: Flintstone
telephoneNumber: +1 555 1234
telephoneNumber: +1 555 5432

Schema validation takes place for the attribute values and that attributes
are allowed/required by the objectclass(es); however, the DN itself is not
validated, nor any checks made that the RDN is present as an attribute
(since this is one of the more stupid parts of the LDAP/X500 data model)
