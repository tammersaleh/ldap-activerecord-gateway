CHANGES FROM VERSION 0.2 TO VERSION 0.3
---------------------------------------

There have been substantial changes to ruby-ldapserver between version 0.2
and version 0.3. If you have not been using 0.2, you can skip this section.

Major API changes:

* I have renamed module LDAPServer to module LDAP::Server, This means e.g.
require 'ldapserver/connection' becomes require 'ldap/server/connection'

* I have moved the result exceptions to be subclasses of LDAP::ResultError,
for consistency with ruby-ldap, and named under LDAP::ResultError::<name> to
group them together. Everything else remains under LDAP::Server.

* The format of the parsed 'filter' parameter to Operation#search has
changed. See filter.rb. In particular, the format of a :substrings filter
has been changed (simplified).

* The format of the 'modinfo' parameter to Operation#modify has changed. See
the comment above 'def modify' in operation.rb

* Attribute names are no longer automatically downcased. If you are running
with a schema, however, then they will be converted into their preferred
forms. That is, "OBJECTCLASS" will become "objectClass", "CommonName" will
become "cn", and so on.

Improvements include:

* There is now an explicit object representing a server instance:
"LDAP::Server". This bundles together the root DSE, the schema (if used),
the subclass of Operation which you wish to use, and various other
parameters such as ssl certificate data. It has methods run_tcpserver and
run_prefork, making it straightforward to start a server. Both support SSL
on connect. You can do require 'ldap/server' to get all the essential
libraries for a server.

* LDAP::Server :user and :group settings let you drop privileges after
binding to port 389.

* Schema support. Can load schemas in OpenLDAP format, publish them via
LDAP, validate add/modify operations, use them to map attribute names to
their 'standard' versions (e.g. "commonname" becomes "cn"), and perform
case-insensitive comparisons where the schema mandates this. See classes
LDAP::Server::Schema, LDAP::Server::ObjectClass, LDAP::Server::AttributeType,
LDAP::Server::Syntax, LDAP::Server::MatchingRule, and examples/rbslapd3.rb.

What is it?
-----------

ruby-ldapserver is a lightweight, pure Ruby skeleton for implementing LDAP
server applications. It is intended primarily for when you wish to build a
gateway from LDAP queries into some other protocol or database; it does not
attempt to be a full implementation of the standard LDAP data model itself
(although you could build one using this as a frontend)

The Connection class handles incoming connections, decodes ASN1-formatted
LDAP requests, and creates an Operation object for each request. The
Operation object further parses the ASN1 request and invokes methods which
you override to perform useful work. Responses and exceptions are converted
back into ASN1 and returned to the client. Optionally, a collection of
objects can be used to implement a Schema (e.g. normalize attribute names,
validate add and modify operations, perform appropriate matching operations)

Since it's written entirely in Ruby, it benefits from Ruby's threading
engine.

Target audience
---------------

Technically-savvy Ruby applications developers; the sort of people who are
happy to read RFCs and read code to work out what it does :-)

The examples/ directory contains a few minimal LDAP servers which you can
use as a starting point.

Status
------

This is an early release. It works for me as an LDAP protocol convertor; the
Schema stuff has not been heavily tested by me.

Libraries
---------

ASN1 encoding and decoding is done using the 'openssl' extension, which is
standard in the Ruby 1.8.2 base distribution. To check you have it, you
should be able to run `ruby -ropenssl -e puts` with no error.

However, I've found in the past that Linux machines don't always build the
openssl extension when compiling Ruby from source. With Red Hat 9, the
solution for me was, when building Ruby itself:

    # export CPPFLAGS="-I/usr/kerberos/include"
    # export LDFLAGS="-L/usr/kerberos/lib"
    # ./configure ...etc

If you want to run the test suite then you'll need to install the ruby-ldap
client library, and if you want to run examples/rbslapd3.rb then you'll need
the prefork library. Both are available from <http://raa.ruby-lang.org/>.

Protocol implementation
-----------------------

ruby-ldapserver tries to be a reasonably complete implementation of the
message decoding and encoding components of LDAP. However, it does not
synthesise or directly enforce the LDAP data model. It will advertise a
schema in the root DSE if you configure one, and it provides helper
functions which allow you to validate add and modify operations against a
schema; but it's up to you to use them, if you wish. If you're just using
LDAP as a convenient query interface into some other database, you probably
don't care about schemas.

If your clients permit it, you can violate the LDAP specification further,
eliminating some of the gross design flaws of LDAP. For example, you can
ditch the LDAP idea that a Distinguished Name must consist of
attr=val,attr=val,attr=val... and use whatever is convenient as a primary
key (e.g. "val1,val2,val3" or "id,table_name"). The 'add' operation could
allocate DNs automatically from a sequence. There's no need for the data
duplication where an LDAP entry must contain the same attr=val pair which is
also the entry's RDN. Violations of the LDAP spec in this way are at your
own risk.

Threading issues
----------------

The core of this library is the LDAP::Server::Connection object which handles
communication with a single client, and the LDAP::Server::Operation object
which handles a single request. Because the LDAP protocol allows a client to
send multiple overlapping requests down the same TCP connection, I start a
new Ruby thread for each Operation.

If your Operation object deals with any global shared data, then it needs to
do so in a thread-safe way. If this is new to you then see
<http://www.rubycentral.com/book/tut_threads.html>
<http://www.rubygarden.org/ruby?MultiThreading>

For incoming client connections, I have supplied a simple tcpserver method
which starts a new Ruby thread for each client. This works fine, but in a
multi-CPU system, all LDAP server operations will be processed on one CPU;
also with a very large number of concurrent client connections, you may find
you hit the a max-filedescriptors-per-process limit.

I have also provided a preforking server; see examples/rbslapd3.rb. In this
case, your connections are handled in separate processes so they cannot
share data directly in RAM.

If you are using the default threading tcpserver, then beware that a number
of Ruby extension libraries block the threading interpreter. In particular,
the client library "ruby-ldap" blocks when waiting for a response from a
remote server, since it's a wrapper around a C library which is unaware of
Ruby's threading engine. This can cause your application to 'freeze'
periodically. Either choose client libraries which play well with threading,
or make sure each client is handled in a different process.

For example, when talking to a MySQL database, you might want to choose
"ruby-mysql" (which is a pure Ruby implementation of the MySQL protocol)
rather than "mysql-ruby" (which is a wrapper around the C API, and blocks
while waiting for responses from the server)

Even with something like ruby-mysql, beware DNS lookups: resolver libraries
can block too. There is a pure Ruby resolver replacement in the standard
library: if you do

    require 'resolv-replace'

this changes TCPSocket and friends to use it instead of the default C
resolver. Or you could just hard-code IP addresses, or put entries in
/etc/hosts for the machines you want to contact.

Another threading issue to think about is abandoned and timed-out LDAP
operations. The Connection object handles these by raising an
LDAP::Server::Abandon or LDAP::Server::TimeLimitExceeded exception in the
Operation thread, which you can either ignore or rescue. However, if in
rescuing it you end up putting (say) a SQL connection back into a pool, you
should beware that the SQL connection may still be mid-query, so it's
probably better to discard it and use a fresh one next time.

Performance
-----------

examples/speedtest.rb is a simple client which forks N processes, and in
each process opens an LDAP connection, binds, and sends M search requests
down it.

Using speedtest.rb and rbslapd1.rb, running on the *same* machine
(single-processor AMD Athlon 2500+) I achieve around 800 searches per second
with N=1,M=1000 and 300-400 searches per second with N=10,M=100.

To-do list
----------

- handle and test generation of LDAP referrals properly
- more cases in test suite: abandon, concurrency, performance tests, error
  handling
- extensible match filters
- extended operations
  RFC 2830 - Start TLS
  RFC 3062 - password modify
  RFC 2839 - whoami
  RFC 3909 - cancel

References
----------

- ftp://ftp.isi.edu/in-notes/rfc2251.txt (base protocol)
- ftp://ftp.isi.edu/in-notes/rfc2252.txt (schema)
- ftp://ftp.isi.edu/in-notes/rfc2253.txt (DN encoding)
- http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
- http://www.itu.int/ITU-T/studygroups/com10/languages/X.690_1297.pdf

Contact
-------

You are very welcome to E-mail me with bug reports, patches, comments and
suggestions for this software. However, please DON'T send me any general
questions about LDAP, how LDAP works, how to apply LDAP in your particular
situation, or questions about any other LDAP software. The `ldap@umich.edu`
mailing list is probably the correct place to ask such questions. See:
<http://listserver.itd.umich.edu/cgi-bin/lyris.pl?enter=ldap>

Brian Candler <B.Candler@pobox.com>
