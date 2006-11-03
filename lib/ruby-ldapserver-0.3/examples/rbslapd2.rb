#!/usr/local/bin/ruby -w

$:.unshift('../lib')
require 'ldap/server'
require 'mysql'                 # <http://www.tmtm.org/en/ruby/mysql/>
require 'thread'
require 'resolv-replace'	# ruby threading DNS client

# An example of an LDAP to SQL gateway. We have a MySQL table which
# contains (login_id,login,passwd) combinations, e.g.
#
#   +----------+----------+--------+
#   | login_id | login    | passwd |
#   +----------+----------+--------+
#   |    1     | brian    | foobar |
#   |    2     | caroline | boing  |
#   +----------+----------+--------+
#
# We support LDAP searches for (uid=login), returning a synthesised DN and
# Maildir attribute, and we support LDAP binds to validate passwords. We
# keep a cache of recent lookups so that a bind to validate a password
# doesn't cause a second SQL query. Since we're multi-threaded, this should
# work even if the bind occurs on a different client connection to the search.
#
# To test:
#    ldapsearch -H ldap://127.0.0.1:1389/ -b "dc=example,dc=com" "(uid=brian)"
#
#    ldapsearch -H ldap://127.0.0.1:1389/ -b "dc=example,dc=com" \
#       -D "id=1,dc=example,dc=com" -W "(uid=brian)"

$debug = true
SQL_CONNECT = ["1.2.3.4", "myuser", "mypass", "mydb"]
TABLE = "logins"
SQL_POOL_SIZE = 5
PW_CACHE_SIZE = 100
BASEDN = "dc=example,dc=com"
LDAP_PORT = 1389

# A thread-safe pool of persistent MySQL connections

class SQLPool
  def initialize(n, *args)
    @args = args
    @pool = Queue.new		# this is a thread-safe queue
    n.times { @pool.push nil }	# create connections on demand
  end

  def borrow
    conn = @pool.pop || Mysql::new(*@args)
    yield conn
  rescue Exception
    conn = nil			# put 'nil' back into the pool
    raise
  ensure
    @pool.push conn
  end
end    

# An simple LRU cache of username->password. It's linearly searched
# so don't make it too big.

class LRUCache
  def initialize(size)
    @size = size
    @cache = []   # [[key,val],[key,val],...]
    @mutex = Mutex.new
  end

  def add(id,data)
    @mutex.synchronize do
      @cache.delete_if { |k,v| k == id }
      @cache.unshift [id,data]
      @cache.pop while @cache.size > @size
    end
  end

  def find(id)
    @mutex.synchronize do
      index = entry = nil
      @cache.each_with_index do |e, i|
        if e[0] == id
          entry = e
          index = i
          break
        end
      end
      return nil unless index
      @cache.delete_at(index)
      @cache.unshift entry
      return entry[1]
    end
  end
end


class SQLOperation < LDAP::Server::Operation
  def self.setcache(cache,pool)
    @@cache = cache
    @@pool = pool
  end

  # Handle searches of the form "(uid=<foo>)" using SQL backend
  # (uid=foo) => [:eq, "uid", matchobj, "foo"]

  def search(basedn, scope, deref, filter)
    raise LDAP::ResultError::UnwillingToPerform, "Bad base DN" unless basedn == BASEDN
    raise LDAP::ResultError::UnwillingToPerform, "Bad filter" unless filter[0..1] == [:eq, "uid"]
    uid = filter[3]
    @@pool.borrow do |sql|
      q = "select login_id,passwd from #{TABLE} where login='#{sql.quote(uid)}'"
      puts "SQL Query #{sql.object_id}: #{q}" if $debug
      res = sql.query(q)
      res.each do |login_id,passwd|
        @@cache.add(login_id, passwd)
        send_SearchResultEntry("id=#{login_id},#{BASEDN}", {
          "maildir"=>["/netapp/#{uid}/"],
        })
      end
    end
  end

  # Validate passwords

  def simple_bind(version, dn, password)
    return if dn.nil?   # accept anonymous

    raise LDAP::ResultError::UnwillingToPerform unless dn =~ /\Aid=(\d+),#{BASEDN}\z/
    login_id = $1
    dbpw = @@cache.find(login_id)
    unless dbpw
      @@pool.borrow do |sql|
        q = "select passwd from #{TABLE} where login_id=#{login_id}"
        puts "SQL Query #{sql.object_id}: #{q}" if $debug
        res = sql.query(q)
        if res.num_rows == 1
          dbpw = res.fetch_row[0]
          @@cache.add(login_id, dbpw)
        end
      end
    end
    raise LDAP::ResultError::InvalidCredentials unless dbpw and dbpw != "" and dbpw == password
  end
end

# Build the objects we need

cache = LRUCache.new(PW_CACHE_SIZE)
pool = SQLPool.new(SQL_POOL_SIZE, *SQL_CONNECT)
SQLOperation.setcache(cache,pool)

s = LDAP::Server.new(
	:port			=> LDAP_PORT,
	:nodelay		=> true,
	:listen			=> 10,
#	:ssl_key_file		=> "key.pem",
#	:ssl_cert_file		=> "cert.pem",
#	:ssl_on_connect		=> true,
	:operation_class	=> SQLOperation
)
s.run_tcpserver
s.join
