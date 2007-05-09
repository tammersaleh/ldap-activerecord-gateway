#!/usr/bin/env ruby

require "test_helper"
require "daemon"

class DaemonTest < Test::Unit::TestCase
  include Daemon

  should "go through the necessary steps to daemonize a process" do
    Kernel.expects(:fork).times(2).returns(true)
    Kernel.expects(:exit).times(2)
    Process.expects(:setsid)
    File.expects(:umask).with(0)
    Dir.expects(:chdir).with('/')
    
    ObjectSpace.each_object(IO) { |io| io.expects(:close) }
    STDIN.expects( :reopen).with("/dev/null")
    STDOUT.expects(:reopen).with("/dev/null", "a")
    STDERR.expects(:reopen).with("/dev/null", "a")

    daemonize
  end
end