#!/usr/bin/env ruby

class Logger
  attr_accessor :logdev
end

module Daemon
  def daemonize(logger = nil)
    # This causes the grandchild process to be orphaned, 
    # so the init process is responsible for cleaning it up.
    Kernel.fork and Kernel.exit
    Process.setsid
    Kernel.fork and Kernel.exit

    File.umask 0
    Dir.chdir '/'

    ObjectSpace.each_object(IO) do |io|
      unless (logger and logger.logdev.dev == io)
        io.close rescue nil
      end
    end

    STDIN.reopen( '/dev/null')
    STDOUT.reopen('/dev/null', 'a')
    STDERR.reopen('/dev/null', 'a')
  end
end
