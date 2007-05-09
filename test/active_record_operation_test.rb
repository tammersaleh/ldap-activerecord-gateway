#!/usr/bin/env ruby

require "test_helper"
require "mocks/person"
require "active_record_operation"

class ActiveRecordOperationTest < Test::Unit::TestCase
  context "ActiveRecordOperation instance" do
    setup do
      @connection = stub(:opt => {:schema => "foo", :server => "bar"})
      @config = { :basedn => "stuff" }
      @active_record_operation = ActiveRecordOperation.new(@connection, 1, @config, Person, Logger.new('/dev/null'))
    end
    
    should "call super (and set schema and server) on new" do
      assert_equal @connection.opt[:schema], @active_record_operation.schema
      assert_equal @connection.opt[:server], @active_record_operation.server
    end
    
    should "return XXX on parse_filter with 1st filter" do
      @filter = [:or, [:substrings, "mail",      nil, nil, "XXX", nil], 
                      [:substrings, "cn",        nil, nil, "XXX", nil], 
                      [:substrings, "givenName", nil, nil, "XXX", nil], 
                      [:substrings, "sn",        nil, nil, "XXX", nil]]
      assert_equal 'XXX', @active_record_operation.parse_filter(@filter)
    end

    should "return XXX on parse_filter with 2nd filter" do
      @filter = [:or, [:substrings, "mail",      nil, "XXX", nil], 
                      [:substrings, "cn",        nil, "XXX", nil], 
                      [:substrings, "givenName", nil, "XXX", nil], 
                      [:substrings, "sn",        nil, "XXX", nil]]
      assert_equal 'XXX', @active_record_operation.parse_filter(@filter)
    end

    should "return XXX on parse_filter with 3rd filter" do
      @filter = [:or, [:substrings, "mail",      nil, "XXX"], 
                      [:substrings, "cn",        nil, "XXX"], 
                      [:substrings, "givenName", nil, "XXX"], 
                      [:substrings, "sn",        nil, "XXX"]]
      assert_equal 'XXX', @active_record_operation.parse_filter(@filter)
    end

    should "return XXX on parse_filter with 4th filter" do
      @filter = [:or, [:substrings, "mail",      nil, nil, "XXX", nil]]
      assert_equal 'XXX', @active_record_operation.parse_filter(@filter)
    end
    
    should "return XXX on parse_filter with 5th filter" do
      @filter = [:or, [:substrings, "givenname", nil, "XXX", nil], 
                      [:substrings, "sn",        nil, "XXX", nil], 
                      [:substrings, "cn",        nil, "XXX", nil], 
                      [:substrings, "mail",      nil, "XXX", nil]]
      assert_equal 'XXX', @active_record_operation.parse_filter(@filter)
    end

    should "raise on parse_filter with 1st bad filter" do
      assert_raise(LDAP::ResultError::UnwillingToPerform) do
        @active_record_operation.parse_filter(nil)
      end
    end

    should "raise on parse_filter with 2nd bad filter" do
      @filter = [:or, [:substrings, "mail", nil, nil]]      
      assert_raise(LDAP::ResultError::UnwillingToPerform) do
        @active_record_operation.parse_filter(@filter)
      end
    end

    should "raise on parse_filter with 3rd bad filter" do
      @filter = [:and, [:substrings, "mail",      nil, nil, "XXX", nil], 
                       [:substrings, "cn",        nil, nil, "XXX", nil], 
                       [:substrings, "givenName", nil, nil, "XXX", nil], 
                       [:substrings, "sn",        nil, nil, "XXX", nil]]
      assert_raise(LDAP::ResultError::UnwillingToPerform) do
        @active_record_operation.parse_filter(@filter)
      end
    end

    should "raise on parse_filter with 4th bad filter" do
      @filter = [:and, [:substrings, "mail",      nil, nil, "XXX", nil], 
                       [:substrings, "cn",        nil, nil, "XXX", nil], 
                       [:substrings, "givenName", nil, nil, "XXX", nil], 
                       [:substrings, "sn",        nil, nil, "XXX", nil]]
      assert_raise(LDAP::ResultError::UnwillingToPerform) do
        @active_record_operation.parse_filter(@filter)
      end
    end

    should "raise on parse_filter with 5th bad filter" do
      @filter = [:or, [:substrings, "silly", nil, nil, "XXX", nil]]
      assert_raise(LDAP::ResultError::UnwillingToPerform) do
        @active_record_operation.parse_filter(@filter)
      end
    end

    should "raise on parse_filter with 6th bad filter" do
      @filter = [:or, [:substrings, nil, nil, nil, "XXX", nil]]
      assert_raise(LDAP::ResultError::UnwillingToPerform) do
        @active_record_operation.parse_filter(@filter)
      end
    end

    context "on search" do
      setup do
        @active_record_operation.attributes = []
        @basedn = "stuff"
        @filter = [:or, [:substrings, "mail", nil, nil, "XXX", nil]]
        @scope = LDAP::Server::WholeSubtree
        @deref = LDAP::Server::DerefAlways
        @active_record_operation.stubs(:send_SearchResultEntry)
      end

      should "deny request with bad basedn" do
        assert_raise(LDAP::ResultError::UnwillingToPerform) do
          @active_record_operation.search("bad", @scope, @deref, @filter)
        end
      end

      should "deny request with BaseObject scope" do
        assert_raise(LDAP::ResultError::UnwillingToPerform) do
          @active_record_operation.search(@basedn, LDAP::Server::BaseObject, @deref, @filter)
        end
      end

      should "call Person.search('XXX')" do
        Person.expects(:search).with('XXX').returns([])
        @active_record_operation.search(@basedn, @scope, @deref, @filter)
      end

      should "raise OperationsError on problems with Person.search" do
        Person.expects(:search).raises(Exception)
        assert_raise(LDAP::ResultError::OperationsError) do
          @active_record_operation.search(@basedn, @scope, @deref, @filter)
        end
      end

      should "return all Person objects from Person.search as ldap entries" do
        Person.search("boo").each do |p|
          e = p.to_ldap_entry
          @active_record_operation.expects(:send_SearchResultEntry).with("uid=#{e["uid"]},#{@basedn}", e)
        end
        @active_record_operation.search(@basedn, @scope, @deref, @filter)
      end
      
      should "raise OperationsError on problems with person.to_ldap_entry" do
        Person.any_instance.stubs(:to_ldap_entry).raises(RuntimeError)
        assert_raise(LDAP::ResultError::OperationsError) do
          @active_record_operation.search(@basedn, @scope, @deref, @filter)
        end
      end
    end
  end
end
