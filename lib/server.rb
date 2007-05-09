$:.unshift File.join(File.dirname(__FILE__))

%w( yaml 
    erb
    etc
    fileutils 
    logger
    thread 
    ruby-ldapserver-0.3/lib/ldap/server 
    ruby-ldapserver-0.3/lib/ldap/server/schema 
    resolv-replace
    active_record_operation
    pid_file 
    daemon
).each do |lib|
  require lib
end    

class Server
  attr_accessor :config, :logger, :pidfile
  include Daemon  

  @@def_config_file_name = File.expand_path(File.join(File.dirname(__FILE__), "..", "conf", "ldap-server.yml"))
  
  def initialize(config_file_name = nil)
    config_file_name ||= @@def_config_file_name
    
    @config = YAML.load(ERB.new(File.read(config_file_name)).result)

    @logger = Logger.new(@config["log_file"] || File.join(@config["rails_dir"], *%w(log ldap-server.log)))
    @logger.level = @config["debug"] ? Logger::DEBUG : Logger::INFO 
    @logger.datetime_format = "%H:%M:%S"    
    @logger.info ""

    require File.join(@config['rails_dir'], 'config', 'environment.rb')
    @logger.info("Cannot load Rails.  Exiting.") and exit 5 unless defined? RAILS_ROOT
    @config.symbolize_keys!

    @pidfile = PidFile.new(@config[:pid_file] || File.join(@config[:rails_dir], *%w(log ldap-server.pid)))
  end
  
  def become_user(username = 'nobody', chroot = false)
    user = Etc::getpwnam(username) 

    Dir.chroot(user.dir) and Dir.chdir('/') if chroot

    Process::initgroups(username, user.gid) 
    Process::Sys::setegid(user.gid) 
    Process::Sys::setgid(user.gid) 
    Process::Sys::setuid(user.uid) 
  end
  
  def start
    pidfile.ensure_empty! "ERROR: It looks like I'm already running.  Not starting."
    
    logger.info "Starting LDAP server on port #{@config[:port]}."
    daemonize(logger)    
    
    # logger = Logger.new(@config[:log_file] || File.join(@config[:rails_dir], *%w(log ldap-server.log)))
    # logger.level = @config[:debug] ? Logger::DEBUG : Logger::INFO 
    # logger.datetime_format = "%H:%M:%S"    
    # logger.info "Reinitialized the logger"
    
    logger.info "Became daemon with process id: #{$$}"
    pidfile.create

    trap("TERM") do 
      logger && logger.info("Received TERM signal.  Exiting.")
      pidfile && pidfile.remove
      exit
    end

    # This is to ensure thread-safety
    ActiveRecord::Base.allow_concurrency = true 

    klass = @config[:active_record_model].constantize
    @logger.info "Access to #{klass.count} #{@config[:active_record_model]} records"

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

  def stop
    if @pidfile.pid
      puts "Sending TERM signal to process #{@pidfile.pid}" if @config[:debug]
      @logger.info("Killing server at #{@pidfile.pid}")
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
end
