#!/usr/local/bin/ruby -w

# This is a trivial LDAP server which just stores directory entries in RAM.
# It does no validation or authentication. This is intended just to
# demonstrate the API, it's not for real-world use!!

$:.unshift('../lib')
$debug = true

require 'ldap/server'

# We subclass the Operation class, overriding the methods to do what we need

class HashOperation < LDAP::Server::Operation
  def initialize(connection, messageID, hash)
    super(connection, messageID)
    @hash = hash   # an object reference to our directory data
  end

  def search(basedn, scope, deref, filter)
    basedn.downcase!

    case scope
    when LDAP::Server::BaseObject
      # client asked for single object by DN
      obj = @hash[basedn]
      raise LDAP::ResultError::NoSuchObject unless obj
      send_SearchResultEntry(basedn, obj) if LDAP::Server::Filter.run(filter, obj)

    when LDAP::Server::WholeSubtree
      @hash.each do |dn, av|
        next unless dn.index(basedn, -basedn.length)    # under basedn?
        next unless LDAP::Server::Filter.run(filter, av)  # attribute filter?
        send_SearchResultEntry(dn, av)
      end

    else
      raise LDAP::ResultError::UnwillingToPerform, "OneLevel not implemented"

    end
  end

  def add(dn, av)
    dn.downcase!
    raise LDAP::ResultError::EntryAlreadyExists if @hash[dn]
    @hash[dn] = av
  end

  def del(dn)
    dn.downcase!
    raise LDAP::ResultError::NoSuchObject unless @hash.has_key?(dn)
    @hash.delete(dn)
  end

  def modify(dn, ops)
    entry = @hash[dn]
    raise LDAP::ResultError::NoSuchObject unless entry
    ops.each do |attr, vals|
      op = vals.shift
      case op 
      when :add
        entry[attr] ||= []
        entry[attr] += vals
        entry[attr].uniq!
      when :delete
        if vals == []
          entry.delete(attr)
        else
          vals.each { |v| entry[attr].delete(v) }
        end
      when :replace
        entry[attr] = vals
      end
      entry.delete(attr) if entry[attr] == []
    end
  end
end

# This is the shared object which carries our actual directory entries.
# It's just a hash of {dn=>entry}, where each entry is {attr=>[val,val,...]}

directory = {}

# Let's put some backing store on it

require 'yaml'
begin
  File.open("ldapdb.yaml") { |f| directory = YAML::load(f.read) }
rescue Errno::ENOENT
end

at_exit do
  File.open("ldapdb.new","w") { |f| f.write(YAML::dump(directory)) }
  File.rename("ldapdb.new","ldapdb.yaml")
end

# Listen for incoming LDAP connections. For each one, create a Connection
# object, which will invoke a HashOperation object for each request.

s = LDAP::Server.new(
	:port			=> 1389,
	:nodelay		=> true,
	:listen			=> 10,
#	:ssl_key_file		=> "key.pem",
#	:ssl_cert_file		=> "cert.pem",
#	:ssl_on_connect		=> true,
	:operation_class	=> HashOperation,
	:operation_args		=> [directory]
)
s.run_tcpserver
s.join
