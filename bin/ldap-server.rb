#!/usr/bin/env ruby
basedir = File.expand_path(File.join(File.dirname(__FILE__), ".."))

require File.join(basedir, "lib", "server")

case ARGV[0]
  when "start":   Server.new(ARGV[1]).start
  when "stop":    Server.new(ARGV[1]).stop
  when "restart": Server.new(ARGV[1]).restart
  else puts "Usage: #{File.basename(__FILE__)} {start|stop|restart} [config file]"
end