#!/usr/bin/env ruby

require "test_helper"

require "server"

require "mocks/pid_file"
require "mocks/ldap_server"

CONFIG_FILE = <<EOD
  rails_dir: #{File.dirname(__FILE__)}/railsdir
  pid_file: /tmp/test.pid
  log_file: /dev/null
  active_record_model: Person
  basedn: dc=exampl,dc=com
  port: 6001
  tcp_nodelay: true
  preforked_threads: 1
  bind_address: 127.0.0.1
  debug: false
EOD


class ServerTest < Test::Unit::TestCase
  context "Server" do
    setup { stub_everything }
    
    should "load environment.rb on new" do
      Server.any_instance.
             expects(:require).
             with("#{File.dirname(__FILE__)}/railsdir/config/environment.rb").
             returns(require("#{File.dirname(__FILE__)}/railsdir/config/environment.rb"))
      server = Server.new("/tmp/stuff.yml")
    end
    
    should "read the config file on new" do
      File.expects(:read).with("/tmp/stuff.yml").returns(CONFIG_FILE)      
      server = Server.new("/tmp/stuff.yml")
    end

    should "create a Logger on new" do
      logger = Logger.new("/dev/null")
      Logger.expects(:new).with("/dev/null").returns(logger)
      server = Server.new("/tmp/stuff.yml")
    end

    should "create a PidFile on new" do
      PidFile.expects(:new).with("/tmp/test.pid").returns(@pid_file)
      server = Server.new("/tmp/stuff.yml")
    end
    
  end
  
  context "A Server instance" do
    setup do 
      stub_everything 
      @server = Server.new("/tmp/stuff.yml")
    end
    
    should "call pidfile.ensure_empty! on start" do
      @server.pidfile.expects(:ensure_empty!)
      @server.start
    end

    should "call pidfile.create on start" do
      @server.pidfile.expects(:create)
      @server.start
    end

    should "call daemonize on start" do
      @server.expects(:daemonize)
      @server.start
    end
    
    should "trap TERM signal" do
      @server.expects(:trap).with("TERM")
      @server.start
    end
    
    should "call LDAP::Server.new on start" do
      LDAP::Server.expects(:new).returns(@ldap_server)
      @server.start
    end
    
    should "tell ActiveRecord to allow concurrency" do
      ActiveRecord::Base.expects(:allow_concurrency=).with(true)
      @server.start
    end

    should "send kill sig to pid in pidfile on stop" do
      @server.pidfile.expects(:pid).at_least_once.returns("1234567890")
      Process.expects(:kill).with("TERM", "1234567890".to_i)
      @server.stop
    end
  end
  
  private
  
  def stub_everything
    @pid_file = MockPidFile.new
    @ldap_server = MockLDAPServer.new

    PidFile.stubs(:new).returns(@pid_file)
    LDAP::Server.stubs(:new).returns(@ldap_server)
    File.stubs(:read).with("/tmp/stuff.yml").returns(CONFIG_FILE)
    Server.any_instance.stubs(:daemonize).returns(true)
  end
end