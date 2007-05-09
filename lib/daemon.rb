#!/usr/bin/env ruby

class Logger
  attr_accessor :logdev
end

module Daemon
  def daemonize(logger = nil)
    # This causes the grandchild process to be orphaned, 
    # so the init process is responsible for cleaning it up.
    logger.debug("Forking") if logger
    Kernel.fork and Kernel.exit
    
    logger.debug("Becoming session leader") if logger
    Process.setsid
    
    logger.debug("Forking again") if logger
    Kernel.fork and Kernel.exit

    logger.debug("Setting umask") if logger
    File.umask 0

    logger.debug("changing to /") if logger
    Dir.chdir '/'

    logger.debug("Closing all IO objects") if logger
    ObjectSpace.each_object(IO) do |io|
      unless (logger and logger.logdev.dev == io)
        io.close rescue nil
      end
    end

    logger.debug("Reopening stdio") if logger
    STDIN.reopen( '/dev/null')
    STDOUT.reopen('/dev/null', 'a')
    STDERR.reopen('/dev/null', 'a')
  end
end
