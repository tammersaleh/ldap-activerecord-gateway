class Server
  def initialize(opts = {})
    load_libraries
    
    basedir     = opts[:basedir]     || File.expand_path(File.join(File.dirname(__FILE__), ".."))
    config_file = opts[:config_file] || File.expand_path(File.join(basedir, "conf", "ldap-server.yml"))
        
    # Load the config file
    @config = YAML.load_file(config_file).symbolize_keys

    @logger = Logger.new("#{basedir}/log/ldap-server.log")
    @logger.level = @config[:debug] ? Logger::DEBUG : Logger::INFO 
    @logger.datetime_format = "%H:%M:%S"    
    @logger.info ""

    require "#{@config[:rails_dir]}/config/environment.rb"
    @logger.info("Cannot load Rails.  Exiting.") and exit 5 unless defined? RAILS_ENV

    @pidfile = Pidfile.new("#{basedir}/var/ldap-server.pid")
    @logger.info "Initialized Server"
  end

  def start
    daemonize do
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
  
  private
    
  def daemonize
    if @pidfile.pid
      puts "ERROR: It looks like I'm already running as #{@pidfile.pid}.  Not starting."
      exit 1
    end

    @logger.info "Starting LDAP server on port #{@config[:port]}."
    fork do
      Process.setsid
      exit if fork

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
      
      yield
    end
  end

  def load_libraries
    $:.unshift File.expand_path(File.join(File.dirname(__FILE__), "ruby-ldapserver-0.3", "lib"))
    %w{ yaml 
        fileutils 
        logger
        hash_extensions
        ldap/server 
        ldap/server/schema 
        thread 
        resolv-replace
        pid-file 
        active-record-operation
      }.each do |lib|
      require lib
    end    
  end
end
