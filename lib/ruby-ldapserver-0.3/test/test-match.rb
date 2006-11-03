$:.unshift('../lib').uniq!
require 'ldap/server/match'
require 'test/unit'

class MatchTest < Test::Unit::TestCase

  def test_caseIgnoreOrderingMatch
    s = LDAP::Server::MatchingRule.find("2.5.13.3")
    assert_equal(LDAP::Server::MatchingRule, s.class)
    assert_equal("caseIgnoreOrderingMatch", s.name)
    assert_equal("( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", s.to_def)
    assert_equal(true, s.le(["foobar","wibble"], "ghi"))
    assert_equal(true, s.le(["FOOBAR","WIBBLE"], "ghi"))
    assert_equal(true, s.le(["foobar","wibble"], "GHI"))
    assert_equal(true, s.le(["FOOBAR","WIBBLE"], "GHI"))
    assert_equal(false, s.le(["foobar","wibble"], "fab"))
    assert_equal(false, s.le(["FOOBAR","WIBBLE"], "fab"))
    assert_equal(false, s.le(["foobar","wibble"], "FAB"))
    assert_equal(false, s.le(["FOOBAR","WIBBLE"], "FAB"))
  end

  def test_caseIgnoreSubstringsMatch
    s = LDAP::Server::MatchingRule.find("2.5.13.4")
    assert_equal(LDAP::Server::MatchingRule, s.class)
    assert_equal("caseIgnoreSubstringsMatch", s.name)
    assert_equal(true, s.substrings(["foobar","wibble"], nil, "oob", nil))
    assert_equal(true, s.substrings(["foobar","wibble"], nil, "foo", nil))
    assert_equal(true, s.substrings(["foobar","wibble"], nil, "bar", nil))
    assert_equal(true, s.substrings(["foobar","wibble"], "wib", nil))
    assert_equal(true, s.substrings(["foobar","wibble"], nil, "ar"))
    assert_equal(true, s.substrings(["foobar","wibble"], "wib", "ble"))
    assert_equal(true, s.substrings(["foobar","wibble"], nil, "oo", "bar"))
    assert_equal(false, s.substrings(["foobar","wibble"], nil, "ooz", nil))
    assert_equal(false, s.substrings(["foobar","wibble"], nil, "foz", nil))
    assert_equal(false, s.substrings(["foobar","wibble"], nil, "zar", nil))
    assert_equal(false, s.substrings(["foobar","wibble"], "bar", nil))
    assert_equal(false, s.substrings(["foobar","wibble"], nil, "oob"))
    assert_equal(false, s.substrings(["foobar","wibble"], "foo", "ble"))
    assert_equal(false, s.substrings(["foobar","wibble"], "foo", "obar"))
  end

  def test_unknown
    s = LDAP::Server::MatchingRule.find("1.4.7.1")
    assert_equal(nil, s)  ## this may change to generate a default object
  end

  def test_nil
    s = LDAP::Server::MatchingRule.find(nil)
    assert_equal(nil, s)
  end

  def test_from_def
    s = LDAP::Server::MatchingRule.from_def("( 1.2.3 NAME ( 'wibble' 'bibble' ) DESC 'foobar' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )")
    assert_equal("1.2.3", s.oid)
    assert_equal(['wibble','bibble'], s.names)
    assert_equal('wibble', s.to_s)
    assert_equal("foobar", s.desc)
    assert_equal("IA5 String", s.syntax.desc)
  end
end
