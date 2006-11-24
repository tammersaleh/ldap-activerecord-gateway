#!/usr/bin/env ruby

MYNAME  = File.basename(__FILE__)
BASEDIR = File.expand_path(File.join(File.dirname(__FILE__), ".."))
Dir.chdir BASEDIR

# Setup paths
$:.unshift "#{BASEDIR}/lib/ruby-ldapserver-0.3/lib/"
$:.unshift "#{BASEDIR}/lib"

# Load libraries
%w{ yaml 
    fileutils 
    ldap/server 
    ldap/server/schema 
    thread 
    resolv-replace
    pid-file 
    active-record-operation
  }.each do |lib|
  require lib
end

if (ARGV.size != 1) || !(%w{start stop restart}.include? ARGV[0])
  puts "Usage:\n  #{MYNAME} [start|stop|restart]"
  exit 3
end

# Load the config file
@config = YAML.load_file("#{BASEDIR}/conf/ldap-server.yml")

require "#{@config["rails_dir"]}/config/environment.rb"
@config.symbolize_keys!
$debug = @config[:debug] # This global needs to be setup for the ruby-ldapserver library

raise RuntimeError, "Cannot load rails." unless defined? RAILS_ENV

@pidfile = Pidfile.new("#{BASEDIR}/var/ldap-server.pid")
@logger  = Logger.new("#{BASEDIR}/log/ldap-server.log")
@logger.level = $debug ? Logger::DEBUG : Logger::INFO 
@logger.datetime_format = "%H:%M:%S"

def start
  if @pidfile.pid
    puts "ERROR: It looks like I'm already running as #{@pidfile.pid}.  Not starting."
    exit 1
  end

  @logger.info ""
  @logger.info "Starting LDAP server on port #{@config[:port]}."
  fork do
    Process.setsid
    exit if fork
    
    # This is to ensure thread-safety
    ActiveRecord::Base.allow_concurrency = true 
    
    klass = @config[:active_record_model].constantize
    @logger.info "Access to #{klass.count} #{@config[:active_record_model]} records"

    @pidfile.create
    @logger.info "Became daemon with process id: #{$$}"

    File.umask 0000

    STDIN.reopen "/dev/null"
    STDOUT.reopen "/dev/null", "a"
    STDERR.reopen STDOUT
    
    trap("TERM") do 
      @logger  && @logger.info("Received TERM signal.  Exiting.")
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