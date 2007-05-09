RAILS_ENV = "text"
RAILS_ROOT = File.expand_path(File.dirname(__FILE__))

require 'rubygems'
require 'active_support'
require File.join(RAILS_ROOT, "..", "..", "mocks", "active_record_base")
require File.join(RAILS_ROOT, "..", "..", "mocks", "person")