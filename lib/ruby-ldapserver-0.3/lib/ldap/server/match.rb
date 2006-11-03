require 'ldap/server/syntax'
require 'ldap/server/result'

module LDAP
class Server

  # A class which holds LDAP MatchingRules. For now there is a global pool
  # of MatchingRule objects (rather than each Schema object having
  # its own pool)

  class MatchingRule
    attr_reader :oid, :names, :syntax, :desc, :obsolete

    # Create a new MatchingRule object

    def initialize(oid, names, syntax, desc=nil, obsolete=false, &blk)
      @oid = oid
      @names = names
      @names = [@names] unless @names.is_a?(Array)
      @desc = desc
      @obsolete = obsolete
      @syntax = LDAP::Server::Syntax.find(syntax)  # creates new obj if reqd
      @def = nil
      # initialization hook
      self.instance_eval(&blk) if blk
    end

    def name
      (@names && names[0]) || @oid
    end

    def to_s
      (@names && names[0]) || @oid
    end

    def normalize(x)
      x
    end

    # Create a new MatchingRule object, given its description string

    def self.from_def(str, &blk)
      m = LDAP::Server::Syntax::MatchingRuleDescription.match(str)
      raise LDAP::ResultError::InvalidAttributeSyntax,
        "Bad MatchingRuleDescription #{str.inspect}" unless m
      new(m[1], m[2].scan(/'(.*?)'/).flatten, m[5], m[3], m[4], &blk)
    end

    def to_def
      return @def if @def
      ans = "( #{@oid} "
      if names.nil? or @names.empty?
        # nothing
      elsif @names.size == 1
        ans << "NAME '#{@names[0]}' "
      else
        ans << "NAME ( "
        @names.each { |n| ans << "'#{n}' " }
        ans << ") "
      end
      ans << "DESC '#@desc' " if @desc
      ans << "OBSOLETE " if @obsolete
      ans << "SYNTAX #@syntax " if @syntax
      ans << ")"
      @def = ans
    end

    @@rules = {}    # oid / name / alias => object

    # Add a new matching rule

    def self.add(*args, &blk)
      s = new(*args, &blk)
      @@rules[s.oid] = s
      return if s.names.nil?
      s.names.each do |n|
        @@rules[n.downcase] = s
      end
    end

    # Find a MatchingRule object given a name or oid, or return nil
    # (? should we create one automatically, like Syntax)

    def self.find(x)
      return x if x.nil? or x.is_a?(LDAP::Server::MatchingRule)
      @@rules[x.downcase]
    end

    # Return all known matching rules

    def self.all_matching_rules
      @@rules.values.uniq
    end

    # Now some things we can mixin to a MatchingRule when needed.
    # Replace 'normalize' with a function which gives the canonical
    # version of a value for comparison.

    module Equality
      def eq(vals, m)
        return false if vals.nil?
        m = normalize(m)
        vals.each { |v| return true if normalize(v) == m }
        return false
      end
    end

    module Ordering
      def ge(vals, m)
        return false if vals.nil?
        m = normalize(m)
        vals.each { |v| return true if normalize(v) >= m }
        return false
      end

      def le(vals, m)
        return false if vals.nil?
        m = normalize(m)
        vals.each { |v| return true if normalize(v) <= m }
        return false
      end
    end

    module Substrings
      def substrings(vals, *ss)
        return false if vals.nil?

        # convert the condition list into a regexp
        re = []
        re << "^#{Regexp.escape(normalize(ss[0]).to_s)}" if ss[0]
        ss[1..-2].each { |s| re << Regexp.escape(normalize(s).to_s) }
        re << "#{Regexp.escape(normalize(ss[-1]).to_s)}$" if ss[-1]
        re = Regexp.new(re.join(".*"))

        vals.each do |v|
          v = normalize(v).to_s
          return true if re.match(v)
        end
        return false
      end
    end # module Substrings

    class DefaultMatchingClass
      include MatchingRule::Equality
      include MatchingRule::Ordering
      include MatchingRule::Substrings
      def normalize(x)
        x
      end
    end

    DefaultMatch = DefaultMatchingClass.new

  end # class MatchingRule

  #
  # And now, here are some matching rules you can use (RFC2252 section 8)
  #

  class MatchingRule

    add('2.5.13.0', 'objectIdentifierMatch', '1.3.6.1.4.1.1466.115.121.1.38') do
      extend Equality
    end
    # FIXME: Filters should return undef if the OID is not in the schema
    # (which means passing in the schema to every equality test)

    add('2.5.13.1', 'distinguishedNameMatch', '1.3.6.1.4.1.1466.115.121.1.12') do
      extend Equality
    end
    # FIXME: Distinguished Name matching is supposed to parse the DN into
    # its parts and then apply the schema equality rules to each part
    # (i.e. some parts may be case-sensitive, others case-insensitive)
    # This is just one of the many nonsense design decisions in LDAP :-(

    # How is a DirectoryString different to an IA5String or a PrintableString?

    module StringTrim
      def normalize(x); x.gsub(/^\s*|\s*$/, '').gsub(/\s+/,' '); end
    end

    module StringDowncase
      def normalize(x); x.downcase.gsub(/^\s*|\s*$/, '').gsub(/\s+/,' '); end
    end

    add('2.5.13.2', 'caseIgnoreMatch', '1.3.6.1.4.1.1466.115.1') do
      extend Equality
      extend StringDowncase
    end

    module Integer
      def normalize(x); x.to_i; end
    end

    add('2.5.13.8', 'numericStringMatch', '1.3.6.1.4.1.1466.115.121.1.36') do
      extend Equality
      extend Integer
    end

    # TODO: Add semantics for these (difficult since RFC2252 doesn't give
    # them, so we presumably have to go through X.500)
    add('2.5.13.11', 'caseIgnoreListMatch', '1.3.6.1.4.1.1466.115.121.1.41')
    add('2.5.13.14', 'integerMatch', '1.3.6.1.4.1.1466.115.121.1.27') do
      extend Equality
      extend Integer
    end
    add('2.5.13.16', 'bitStringMatch', '1.3.6.1.4.1.1466.115.121.1.6')
    add('2.5.13.20', 'telephoneNumberMatch', '1.3.6.1.4.1.1466.115.121.1.50') do
      extend Equality
      extend StringTrim
    end
    add('2.5.13.22', 'presentationAddressMatch', '1.3.6.1.4.1.1466.115.121.1.43')
    add('2.5.13.23', 'uniqueMemberMatch', '1.3.6.1.4.1.1466.115.121.1.34')
    add('2.5.13.24', 'protocolInformationMatch', '1.3.6.1.4.1.1466.115.121.1.42')
    add('2.5.13.27', 'generalizedTimeMatch', '1.3.6.1.4.1.1466.115.121.1.24') { extend Equality }

    # IA5 stuff. FIXME: What's the correct way to 'downcase' UTF8 strings?

    module IA5Trim
      def normalize(x); x.gsub(/^\s*|\s*$/u, '').gsub(/\s+/u,' '); end
    end

    module IA5Downcase
      def normalize(x); x.downcase.gsub(/^\s*|\s*$/u, '').gsub(/\s+/u,' '); end
    end

    add('1.3.6.1.4.1.1466.109.114.1', 'caseExactIA5Match', '1.3.6.1.4.1.1466.115.121.1.26') do
      extend Equality
      extend IA5Trim
    end

    add('1.3.6.1.4.1.1466.109.114.2', 'caseIgnoreIA5Match', '1.3.6.1.4.1.1466.115.121.1.26') do
      extend Equality
      extend IA5Downcase
    end

    add('2.5.13.28', 'generalizedTimeOrderingMatch', '1.3.6.1.4.1.1466.115.121.1.24') { extend Ordering }
    add('2.5.13.3', 'caseIgnoreOrderingMatch', '1.3.6.1.4.1.1466.115.121.1.15') do
      extend Ordering
      extend StringDowncase
    end

    add('2.5.13.4', 'caseIgnoreSubstringsMatch', '1.3.6.1.4.1.1466.115.121.1.58') do
      extend Substrings
      extend StringDowncase
    end
    add('2.5.13.21', 'telephoneNumberSubstringsMatch', '1.3.6.1.4.1.1466.115.121.1.58') do
      extend Substrings
    end
    add('2.5.13.10', 'numericStringSubstringsMatch', '1.3.6.1.4.1.1466.115.121.1.58') do
      extend Substrings
    end

    # from OpenLDAP
    add('1.3.6.1.4.1.4203.1.2.1', 'caseExactIA5SubstringsMatch', '1.3.6.1.4.1.1466.115.121.1.26') do
      extend Substrings
      extend IA5Trim
    end
    add('1.3.6.1.4.1.1466.109.114.3', 'caseIgnoreIA5SubstringsMatch', '1.3.6.1.4.1.1466.115.121.1.26') do
      extend Substrings
      extend IA5Downcase
    end
    add('2.5.13.5', 'caseExactMatch', '1.3.6.1.4.1.1466.115.121.1.15') { extend Equality }
    add('2.5.13.6', 'caseExactOrderingMatch', '1.3.6.1.4.1.1466.115.121.1.15') { extend Ordering }
    add('2.5.13.7', 'caseExactSubstringsMatch', '1.3.6.1.4.1.1466.115.121.1.58') { extend Substrings }
    add('2.5.13.9', 'numericStringOrderingMatch', '1.3.6.1.4.1.1466.115.121.1.36') { extend Ordering; extend Integer }
    add('2.5.13.13', 'booleanMatch', '1.3.6.1.4.1.1466.115.121.1.7') do
      extend Equality
      def self.normalize(x)
        return true if x == 'TRUE'
        return false if x == 'FALSE'
        x
      end
    end
    add('2.5.13.15', 'integerOrderingMatch', '1.3.6.1.4.1.1466.115.121.1.27') { extend Ordering; extend Integer }
    add('2.5.13.17', 'octetStringMatch', '1.3.6.1.4.1.1466.115.121.1.40') { extend Equality }
    add('2.5.13.18', 'octetStringOrderingMatch', '1.3.6.1.4.1.1466.115.121.1.40') { extend Ordering }
    add('2.5.13.19', 'octetStringSubstringsMatch', '1.3.6.1.4.1.1466.115.121.1.40') { extend Substrings }

  end # class MatchingRule

end # class Server
end # module LDAP
