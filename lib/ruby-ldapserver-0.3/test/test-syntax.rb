$:.unshift('../lib').uniq!
require 'ldap/server/syntax'
require 'test/unit'

class SyntaxTest < Test::Unit::TestCase

  def test_integer
    s = LDAP::Server::Syntax.find("1.3.6.1.4.1.1466.115.121.1.27")
    assert_equal(LDAP::Server::Syntax, s.class)
    assert_equal("Integer", s.desc)
    assert_equal("( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )", s.to_def)
    assert(!s.nhr)
    assert(s.match("123"))
    assert(!s.match("12A"))
    assert_equal(123, s.value_from_s("123"))
    assert_equal("456", s.value_to_s(456))
    assert_equal("789", s.value_to_s("789"))
  end

  def test_unknown
    s = LDAP::Server::Syntax.find("1.4.7.1")
    assert_equal(LDAP::Server::Syntax, s.class)
    assert_equal("1.4.7.1", s.oid)
    assert_equal("1.4.7.1", s.to_s)
    assert_equal("( 1.4.7.1 )", s.to_def)
    assert_equal("false", s.value_to_s(false))	# generic value_to_s
    assert_equal("true", s.value_from_s("true")) # generic value_from_s
    assert(s.match("123"))			# match anything
  end

  def test_nil
    s = LDAP::Server::Syntax.find(nil)
    assert_equal(nil, s)
  end

  def test_from_def
    s = LDAP::Server::Syntax.from_def("( 1.2.3 DESC 'foobar' )")
    assert_equal("1.2.3", s.oid)
    assert_equal("foobar", s.desc)
  end
end
