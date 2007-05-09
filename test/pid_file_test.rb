#!/usr/bin/env ruby

require 'test_helper.rb'
require 'pid_file'

class PidFileTest < Test::Unit::TestCase
  context "PidFile with a good path" do
    setup do
      @pidfile = PidFile.new('/tmp/pidfile')
      assert_nothing_raised { @pidfile.create }
    end

    should "create pid file on :create" do
      assert File.exists?(@pidfile.file)
    end

    should "return my pid on :pid" do
      pid = nil
      assert_nothing_raised { pid = @pidfile.pid }
      assert_equal $$, pid.to_i
    end
    
    should "remove pid file on :remove" do
      assert_nothing_raised { @pidfile.remove }
      assert ! File.exists?(@pidfile.file)
    end
    
    should "exit on ensure_empty! if pidfile exists" do
      assert_raises(SystemExit) { @pidfile.ensure_empty! }
    end
  end

  context "PidFile with a bad path" do
    setup do
      @pidfile = PidFile.new('/tmp/some/bad/path/pidfile')
    end

    should "raise an exception on :create" do
      assert_raises(Errno::ENOENT) { @pidfile.create }
      assert !File.exists?(@pidfile.file)
    end

    should "return false on :pid" do
      pid = nil
      assert_nothing_raised { pid = @pidfile.pid }
      assert !pid
    end
    
    should "not raise an exception on :remove" do
      assert_nothing_raised { @pidfile.remove }
    end
  end
end