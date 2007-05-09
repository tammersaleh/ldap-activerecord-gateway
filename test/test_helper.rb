require 'test/unit'
require 'rubygems'
require "mocha"

$LOAD_PATH << File.expand_path(File.dirname(__FILE__))
$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__), *%w(.. lib)))

$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__), *%w(.. lib shoulda-2.0.6)))
$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__), *%w(.. lib shoulda-2.0.6 lib)))
require 'init.rb' # requires shoulda