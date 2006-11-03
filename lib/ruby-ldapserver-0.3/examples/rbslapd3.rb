#!/usr/local/bin/ruby -w

# This is similar to rbslapd1.rb but here we use TOMITA Masahiro's prefork
# library: <http://raa.ruby-lang.org/project/prefork/>
# Advantages over Ruby threading:
# - each client connection is handled in its own process; don't need
#   to worry about Ruby thread blocking (except if one client issues
#   overlapping LDAP operations down the same connection, which is uncommon)
# - better scalability on multi-processor systems
# - better scalability on single-processor systems (e.g. shouldn't hit
#   max FDs per process limit)
# Disadvantages:
# - client connections can't share state in RAM. So our shared directory
#   now has to be read from disk, and flushed to disk after every update.
#
# Additionally, I have added schema support. An LDAP v3 client can
# query the schema remotely, and adds/modifies have data validated.

$:.unshift('../lib')

require 'ldap/server'
require 'ldap/server/schema'
require 'yaml'

$debug = nil # $stderr

# An object to keep our in-RAM database and synchronise it to disk
# when necessary

class Directory
  attr_reader :data

  def initialize(filename)
    @filename = filename
    @stat = nil
    update
  end

  # synchronise with directory on disk (re-read if it has changed)

  def update
    begin
      tmp = {}
      sb = File.stat(@filename)
      return if @stat and @stat.ino == sb.ino and @stat.mtime == sb.mtime
      File.open(@filename) do |f|
        tmp = YAML::load(f.read)
        @stat = f.stat
      end
    rescue Errno::ENOENT
    end
    @data = tmp
  end

  # write back to disk

  def write
    File.open(@filename+".new","w") { |f| f.write(YAML::dump(@data)) }
    File.rename(@filename+".new",@filename)
    @stat = File.stat(@filename)
  end

  # run a block while holding a lock on the database

  def lock
    File.open(@filename+".lock","w") do |f|
      f.flock(File::LOCK_EX)  # will block here until lock available
      yield
    end
  end
end

# We subclass the Operation class, overriding the methods to do what we need

class DirOperation < LDAP::Server::Operation
  def initialize(connection, messageID, dir)
    super(connection, messageID)
    @dir = dir
  end

  def search(basedn, scope, deref, filter)
    $debug << "Search: basedn=#{basedn.inspect}, scope=#{scope.inspect}, deref=#{deref.inspect}, filter=#{filter.inspect}\n" if $debug
    basedn.downcase!

    case scope
    when LDAP::Server::BaseObject
      # client asked for single object by DN
      @dir.update
      obj = @dir.data[basedn]
      raise LDAP::ResultError::NoSuchObject unless obj
      ok = LDAP::Server::Filter.run(filter, obj)
      $debug << "Match=#{ok.inspect}: #{obj.inspect}\n" if $debug
      send_SearchResultEntry(basedn, obj) if ok

    when LDAP::Server::WholeSubtree
      @dir.update
      @dir.data.each do |dn, av|
        $debug << "Considering #{dn}\n" if $debug
        next unless dn.index(basedn, -basedn.length)    # under basedn?
        next unless LDAP::Server::Filter.run(filter, av)  # attribute filter?
        $debug << "Sending: #{av.inspect}\n" if $debug
        send_SearchResultEntry(dn, av)
      end

    else
      raise LDAP::ResultError::UnwillingToPerform, "OneLevel not implemented"

    end
  end

  def add(dn, entry)
    entry = @schema.validate(entry)
    entry['createTimestamp'] = [Time.now.gmtime.strftime("%Y%m%d%H%MZ")]
    entry['creatorsName'] = [@connection.binddn.to_s]
    # FIXME: normalize the DN and check it's below our root DN
    # FIXME: validate that a superior object exists
    # FIXME: validate that entry contains the RDN attribute (yuk)
    dn.downcase!
    @dir.lock do
      @dir.update
      raise LDAP::ResultError::EntryAlreadyExists if @dir.data[dn]
      @dir.data[dn] = entry
      @dir.write
    end
  end

  def del(dn)
    dn.downcase!
    @dir.lock do
      @dir.update
      raise LDAP::ResultError::NoSuchObject unless @dir.data.has_key?(dn)
      @dir.data.delete(dn)
      @dir.write
    end
  end

  def modify(dn, ops)
    dn.downcase!
    @dir.lock do
      @dir.update
      entry = @dir.data[dn]
      raise LDAP::ResultError::NoSuchObject unless entry
      entry = @schema.validate(ops, entry)  # also does the update
      entry['modifyTimestamp'] = [Time.now.gmtime.strftime("%Y%m%d%H%MZ")]
      entry['modifiersName'] = [@connection.binddn.to_s]
      @dir.data[dn] = entry
      @dir.write
    end
  end
end

directory = Directory.new("ldapdb.yaml")

schema = LDAP::Server::Schema.new
schema.load_system
schema.load_file("../test/core.schema")
schema.resolve_oids

s = LDAP::Server.new(
	:port			=> 1389,
	:nodelay		=> true,
	:listen			=> 10,
#	:ssl_key_file		=> "key.pem",
#	:ssl_cert_file		=> "cert.pem",
#	:ssl_on_connect		=> true,
	:operation_class	=> DirOperation,
	:operation_args		=> [directory],
	:schema			=> schema,
	:namingContexts		=> ['dc=example,dc=com']
)
s.run_prefork
s.join
