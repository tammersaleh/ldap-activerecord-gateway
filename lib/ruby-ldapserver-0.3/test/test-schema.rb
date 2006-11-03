$:.unshift('../lib').uniq!
require 'ldap/server/schema'
require 'ldap/server/match'
require 'test/unit'

class SchemaTest < Test::Unit::TestCase

  def test_parse_attr
attr = <<ATTR
( 2.5.4.3 NAME 'cn' OBSOLETE EQUALITY 1.2.3 ORDERING 4.5.678 SUBSTR 9.1.1 SYNTAX 4.3.2{58} SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION USAGE userApplications )
ATTR
    a = LDAP::Server::Schema::AttributeType.new(attr)
    assert_equal("2.5.4.3", a.oid)
    assert_equal("cn", a.name)
    assert_equal(["cn"], a.names)
    assert(a.obsolete)
    assert_equal("1.2.3", a.equality)
    assert_equal("4.5.678", a.ordering)
    assert_equal("9.1.1", a.substr)
    assert_equal("4.3.2", a.syntax)
    assert_equal(58, a.maxlen)
    assert(a.singlevalue)
    assert(a.collective)
    assert(a.nousermod)
    assert_equal(:userApplications, a.usage)
    assert_equal(attr.chomp, a.to_def)

attr = <<ATTR
( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s) for which the entity is known by' SUP name )
ATTR
    a = LDAP::Server::Schema::AttributeType.new(attr)
    assert_equal("2.5.4.3", a.oid)
    assert_equal("cn", a.name)
    assert_equal(["cn", "commonName"], a.names)
    assert_equal("RFC2256: common name(s) for which the entity is known by", a.desc)
    assert(! a.obsolete)
    assert_equal("name", a.sup)
    assert(! a.singlevalue)
    assert(! a.collective)
    assert(! a.nousermod)
    assert_equal(attr.chomp, a.to_def)
  end

  def test_parse_objectclass
oc = <<OC
( 0.9.2342.19200300.100.4.19 NAME 'simpleSecurityObject' DESC 'RFC1274: simple security object' SUP top AUXILIARY MUST userPassword )
OC
    a = LDAP::Server::Schema::ObjectClass.new(oc)
    assert_equal("0.9.2342.19200300.100.4.19", a.oid)
    assert_equal("simpleSecurityObject", a.name)
    assert_equal(["simpleSecurityObject"], a.names)
    assert(! a.obsolete)
    assert_equal("RFC1274: simple security object", a.desc)
    assert_equal(["top"], a.sup)
    assert_equal(:auxiliary, a.struct)
    assert_equal(["userPassword"], a.must)
    assert_equal([], a.may)
    assert_equal(oc.chomp, a.to_def)

oc = <<OC
( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )
OC
    a = LDAP::Server::Schema::ObjectClass.new(oc)
    assert_equal("2.5.6.6", a.oid)
    assert_equal("person", a.name)
    assert_equal(["person"], a.names)
    assert(! a.obsolete)
    assert_equal("RFC2256: a person", a.desc)
    assert_equal(["top"], a.sup)
    assert_equal(:structural, a.struct)
    assert_equal(["sn", "cn"], a.must)
    assert_equal(["userPassword","telephoneNumber","seeAlso","description"], a.may)
    assert_equal(oc.chomp, a.to_def)
  end

  def test_loadschema
    s = LDAP::Server::Schema.new
    s.load_system
    s.load_file("core.schema")
    s.resolve_oids
    a = s.find_attrtype("objectclass")
    assert_equal("objectClass", a.name)
    a = s.find_attrtype("COMMONNAME")
    assert_equal(LDAP::Server::Schema::AttributeType, a.class)
    assert_equal("caseIgnoreMatch", a.equality.to_s)
    assert_equal(LDAP::Server::MatchingRule, a.equality.class)
    assert_equal("caseIgnoreSubstringsMatch", a.substr.to_s)
    assert_equal(LDAP::Server::MatchingRule, a.substr.class)
    assert_equal("1.3.6.1.4.1.1466.115.121.1.15", a.syntax.to_s)
    assert_equal(LDAP::Server::Syntax, a.syntax.class)
    assert_equal("cn", a.name)
    a = s.find_attrtype("COUNTRYname")
    assert_equal("c", a.name)
    # I modified core.schema so that countryName has the appropriate syntax
    assert(a.syntax.match("GB"))
    assert(!a.syntax.match("ABC"))
  end

  def test_backwards_api
    s = LDAP::Server::Schema.new
    s.load_system
    assert_equal(['subschema','OpenLDAProotDSE','referral','alias','extensibleObject','top'].sort,
      s.names('objectClasses').sort)
    assert_equal(['dITStructureRules','nameForms','ditContentRules','objectClasses','attributeTypes','matchingRules','matchingRuleUse'],
      s.attr('subschema', 'may'))
    assert_equal([], s.attr('subschema', 'must'))
    assert_equal(nil, s.attr('foo', 'must'))
    assert_equal(['top'], s.sup('extensibleObject'))
  end

  def test_validate
    # FIXME
  end
end
