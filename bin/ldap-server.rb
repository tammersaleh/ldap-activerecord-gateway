#!/usr/bin/env ruby

MYNAME  = File.basename(__FILE__)
BASEDIR = File.expand_path(File.join(File.dirname(__FILE__), ".."))
Dir.chdir BASEDIR

$:.unshift "#{BASEDIR}/lib"
require 'server'

if (ARGV.size != 1) || !(%w{start stop restart}.include? ARGV[0])
  puts "Usage:\n  #{MYNAME} [start|stop|restart]"
  exit 3
end


case ARGV[0]
  when "start":   start
  when "stop":    stop
  when "restart": restart
end