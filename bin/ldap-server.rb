#!/usr/bin/env ruby

$debug = false # Server complains without this set.

MYNAME = File.basename(__FILE__)

if (ARGV.size != 1) || !(%w{start stop restart}.include? ARGV[0])
  puts "Usage:\n  #{MYNAME} [start|stop|restart]"
  exit 3
end

BASEDIR = File.expand_path(File.join(File.dirname(__FILE__), ".."))
# Load libraries
$:.unshift("#{BASEDIR}/lib/ruby-ldapserver-0.3/lib/")
%w{yaml fileutils ldap/server ldap/server/schema thread resolv-replace}.each do |lib|
  puts "Loading #{lib}" if $debug
  require lib
end

# Load the config file
@config = YAML.load_file("#{BASEDIR}/conf/ldap-server.yml")

require "#{@config["rails_dir"]}/config/environment.rb"
@config.symbolize_keys!

# Just to be sure.
raise RuntimeError, "Cannot load rails." unless defined? RAILS_ENV

class ActiveRecordOperation < LDAP::Server::Operation
  def initialize(connection, messageID, config_hash, ar_class, logger)
    @config = config_hash
    @ar_class = ar_class
    @logger = logger
    @logger.debug "Received connection request (#{messageID})."
    super(connection, messageID)
  end
  
  def search(basedn, scope, deref, filter)
    @logger.info "Received search request."
    @logger.debug "Filter: #{filter.inspect}"
    # This is needed to force the ruby ldap server to return our parameters, 
    # even though the client didn't explicitly ask for them
    @attributes << "*"
    if basedn != @config[:basedn]
      @logger.info "Denying request with missmatched basedn (requested #{@config[:basedn]})"
      raise LDAP::ResultError::UnwillingToPerform, "Bad base DN" unless basedn == @config[:basedn]
    end

    if scope == LDAP::Server::BaseObject
        @logger.info "Denying request for BaseObject"
        raise LDAP::ResultError::UnwillingToPerform, "BaseObject not implemented"
    elsif scope == LDAP::Server::SingleLevel
        @logger.info "Denying request for SingleLevel"
        raise LDAP::ResultError::UnwillingToPerform, "OneLevel not implemented"
    end

    # format of mozilla and OS X address book searches are always this: 
    # [:or, [:substrings, "mail",      nil, nil, "XXX", nil], 
    #       [:substrings, "cn",        nil, nil, "XXX", nil], 
    #       [:substrings, "givenName", nil, nil, "XXX", nil], 
    #       [:substrings, "sn",        nil, nil, "XXX", nil]]
    # (with the order of the subgroups maybe turned around)
    
    unless (filter[0] == :or) and (filter[1..4].transpose[0] == ([:substrings] * 4))
      @logger.info "Denying complex query (error 1)"
      raise LDAP::ResultError::UnwillingToPerform, "This query is way too complex: #{filter.inspect}"
    end
    
    query_string = filter[1][4]
      
    unless (filter[1..4].transpose[4] == ([query_string] * 4))
      @logger.info "Denying complex query (error 2)"
      raise LDAP::ResultError::UnwillingToPerform, "Seriously, I can only handle simple queries: #{filter.inspect}"
    end

    @logger.debug "Running #{@ar_class.name}.search(#{query_string})"
    begin
      @records = @ar_class.search(query_string)
    rescue
      @logger.error "ERROR running #{@ar_class.name}.search(#{query_string}): #{$!}"
      raise LDAP::ResultError::OperationsError, "Error encountered during processing."
    end 
    begin
      @logger.info "Returning #{@records.size} records matching \"#{query_string}\"."
      @records.each do |record|
        ret = record.to_ldap_entry
        ret_basedn = "uid=#{ret["uid"]},#{@config[:basedn]}"
        @logger.debug "Sending #{ret_basedn} - #{ret.inspect}" 
        send_SearchResultEntry(ret_basedn, ret)
      end
    rescue
      @logger.error "ERROR converting AR instance to ldap entry: #{$!}"
      raise LDAP::ResultError::OperationsError, "Error encountered during processing."
    end      
  end
end

class Pidfile
  # Note:  should really daemonize correctly and all that.  Whatever.
  def initialize(file)
    @file = file 
  end
  
  def pid
    File.file?(@file) and IO.read(@file) 
  rescue 
    puts "ERROR: attempt to read contents of #{@file} failed."
  end
  
  def remove
    if self.pid
      FileUtils.rm @file 
    end
  rescue 
    puts "ERROR: remove #{@file} failed."
  end
  
  def create
    File.open(@file, "w") { |f| f.write($$) }
  rescue 
    puts "ERROR: attempt to write #{file} failed."
  end
end

@pidfile = Pidfile.new("#{BASEDIR}/var/ldap-server.pid")
@logger = Logger.new("#{BASEDIR}/log/ldap-server.log")
@logger.level = $debug ? Logger::DEBUG : Logger::INFO 
@logger.datetime_format = "%H:%M:%S"

def start
  if @pidfile.pid
    puts "ERROR: It looks like I'm already running as #{@pidfile.pid}.  Not starting."
    exit 1
  end

  @logger.info "Starting LDAP server on port #{@config[:port]}."
  fork do
    Process.setsid
    exit if fork

    klass = @config[:active_record_model].constantize
    @logger.info "Access to #{klass.count} #{@config[:active_record_model]} records"

    @pidfile.create
    @logger.info "Became daemon with process id: #{$$}"

    Dir.chdir BASEDIR
    File.umask 0000

    STDIN.reopen "/dev/null"
    STDOUT.reopen "/dev/null", "a"
    STDERR.reopen STDOUT
    
    trap("TERM") do 
      @logger.info "Received TERM signal.  Exiting."
      @pidfile && @pidfile.remove
      exit
    end
    
    s = LDAP::Server.new(
    	:port			        => @config[:port],
    	:bindaddr         => @config[:bind_address],
    	:nodelay		      => @config[:tcp_nodelay],
    	:listen			      => @config[:prefork_threads],
    	:namingContexts		=> [@config[:basedn]],
    	:user             => @config[:user],
    	:group            => @config[:group],
    	:operation_class	=> ActiveRecordOperation,
    	:operation_args		=> [@config, klass, @logger]
    )
    s.run_tcpserver
    s.join
  end
end

def stop
  if @pidfile.pid
    puts "Sending TERM signal to process #{@pidfile.pid}"
    Process.kill("TERM", @pidfile.pid.to_i)
  else
    puts "Can't find pid.  Are you sure I'm running?"
  end
end

def restart
  stop
  sleep 5
  start
end

case ARGV[0]
when "start":   start
when "stop":    stop
when "restart": restart
end