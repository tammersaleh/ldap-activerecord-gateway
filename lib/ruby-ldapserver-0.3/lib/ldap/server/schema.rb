require 'ldap/server/syntax'
require 'ldap/server/result'

module LDAP
class Server

  # This object represents an LDAP schema: that is, a collection of
  # objectclasses and attributetypes. Methods are provided for loading
  # the schema (from a string or a disk file), and validating an av-hash
  # against it.

  class Schema

    SUBSCHEMA_ENTRY_ATTR = 'cn'
    SUBSCHEMA_ENTRY_VALUE = 'Subschema'

    def initialize
      @attrtypes = {}		# name/alias/oid => AttributeType instance
      @objectclasses = {}	# name/alias/oid => ObjectClass instance
      @subschema_cache = nil
    end

    # return the DN of the subschema subentry

    def subschema_dn
      "#{SUBSCHEMA_ENTRY_ATTR}=#{SUBSCHEMA_ENTRY_VALUE}"
    end

    # Return an av hash object giving the subschema subentry. This is cached, so
    # call Schema#changed if it needs to be rebuilt

    def subschema_subentry
      @subschema_cache ||= {
	'objectClass' => ['top','subschema','extensibleObject'],
	SUBSCHEMA_ENTRY_ATTR => [SUBSCHEMA_ENTRY_VALUE],
	'objectClasses' => all_objectclasses.collect { |s| s.to_def },
	'attributeTypes' => all_attrtypes.collect { |s| s.to_def },
	'ldapSyntaxes' => LDAP::Server::Syntax.all_syntaxes.collect { |s| s.to_def },
	#'matchingRules' =>
	#'matchingRuleUse' =>
      }
    end

    # Clear the subschema subentry cache, so the next time someone requests
    # it, it will be rebuilt

    def changed
      @subschema_cache = nil
    end

    # Add an AttributeType to the schema

    def add_attrtype(str)
      a = AttributeType.new(str)
      @attrtypes[a.oid] = a if a.oid
      a.names.each do |n|
        @attrtypes[n.downcase] = a
      end
    end

    # Locate an attributetype object by name/alias/oid (or raise exception)

    def find_attrtype(n)
      return n if n.nil? or n.is_a?(LDAP::Server::Schema::AttributeType)
      r = @attrtypes[n.downcase]
      raise LDAP::ResultError::UndefinedAttributeType, "Unknown AttributeType #{n.inspect}" unless r
      r
    end

    # Return array of all AttributeType objects in this schema

    def all_attrtypes
      @attrtypes.values.uniq
    end

    # Add an ObjectClass to the schema

    def add_objectclass(str)
      o = ObjectClass.new(str)
      @objectclasses[o.oid] = o if o.oid
      o.names.each do |n|
        @objectclasses[n.downcase] = o
      end
    end

    # Locate an objectclass object by name/alias/oid (or raise exception)

    def find_objectclass(n)
      return n if n.nil? or n.is_a?(LDAP::Server::Schema::ObjectClass)
      r = @objectclasses[n.downcase]
      raise LDAP::ResultError::ObjectClassViolation, "Unknown ObjectClass #{n.inspect}" unless r
      r
    end

    # Return array of all ObjectClass objects in this schema

    def all_objectclasses
      @objectclasses.values.uniq
    end

    # Load an OpenLDAP-format schema from a named file (see notes under 'load')

    def load_file(filename)
      File.open(filename) { |f| load(f) }
    end

    # Load an OpenLDAP-format schema from a string or IO object (anything
    # which responds to 'each_line'). Lines starting 'attributetype'
    # or 'objectclass' contain one of those objects. Does not implement
    # named objectIdentifier prefixes (used in the dyngroup.schema file
    # supplied with openldap, but not documented in RFC2252)
    #
    # Note: RFC2252 is strict about the order in which the elements appear,
    # and so are we, but OpenLDAP is not. This means that a schema which
    # works in OpenLDAP might not load here. For example, RFC2252 says
    # that in an objectclass description, "SUP" must come before "MAY";
    # if they are the other way round, our regexp-based parser will not
    # accept it. The solution is simply to modify the definition so that
    # the elements appear in the correct order.

    def load(str_or_io)
      meth = :junk_line
      data = ""
      str_or_io.each_line do |line|
        case line
        when /^\s*#/, /^\s*$/
          next
        when /^objectclass\s*(.*)$/i
          m = $~
          send(meth, data)
          meth, data = :add_objectclass, m[1]
        when /^attributetype\s*(.*)$/i
          m = $~
          send(meth, data)
          meth, data = :add_attrtype, m[1]
        else
          data << line
        end
      end
      send(meth,data)
      self
    end

    def junk_line(data)
      return if data.empty?
      raise LDAP::ResultError::InvalidAttributeSyntax,
        "Expected 'attributetype' or 'objectclass', got #{data}"
    end
    private :junk_line

    # Load in the base set of objectclasses and attributetypes, being
    # the same set as OpenLDAP preloads internally. Includes objectclasses
    # 'top', 'objectclass'; attributetypes 'objectclass' , 'cn',
    # 'userPassword' and 'distinguishedName'; common operational attributes
    # such as 'modifyTimestamp'; plus extras needed for publishing a v3
    # schema via LDAP

    def load_system
      load(<<EOS)
attributetype ( 1.3.6.1.4.1.250.1.57 NAME 'labeledURI' DESC 'RFC2079: Uniform Resource Identifier with optional label' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 2.5.4.35 NAME 'userPassword' DESC 'RFC2256/2307: password of user' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )
attributetype ( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s) for which the entity is known by' SUP name )
attributetype ( 2.5.4.41 NAME 'name' DESC 'RFC2256: common supertype of name attributes' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )
attributetype ( 2.5.4.49 NAME 'distinguishedName' DESC 'RFC2256: common supertype of DN attributes' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributetype ( 2.16.840.1.113730.3.1.34 NAME 'ref' DESC 'namedref: subordinate referral URL' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE distributedOperation )
attributetype ( 2.5.4.1 NAME ( 'aliasedObjectName' 'aliasedEntryName' ) DESC 'RFC2256: name of aliased object' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' DESC 'RFC2252: LDAP syntaxes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )
attributetype ( 2.5.21.8 NAME 'matchingRuleUse' DESC 'RFC2252: matching rule uses' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 USAGE directoryOperation )
attributetype ( 2.5.21.6 NAME 'objectClasses' DESC 'RFC2252: object classes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )
attributetype ( 2.5.21.5 NAME 'attributeTypes' DESC 'RFC2252: attribute types' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )
attributetype ( 2.5.21.4 NAME 'matchingRules' DESC 'RFC2252: matching rules' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )
attributetype ( 1.3.6.1.1.5 NAME 'vendorVersion' DESC 'RFC3045: version of implementation' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )
attributetype ( 1.3.6.1.1.4 NAME 'vendorName' DESC 'RFC3045: name of implementation vendor' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.4203.1.3.5 NAME 'supportedFeatures' DESC 'features supported by the server' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.14 NAME 'supportedSASLMechanisms' DESC 'RFC2252: supported SASL mechanisms' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion' DESC 'RFC2252: supported LDAP versions' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.7 NAME 'supportedExtension' DESC 'RFC2252: supported extended operations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.13 NAME 'supportedControl' DESC 'RFC2252: supported controls' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts' DESC 'RFC2252: naming contexts' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.6 NAME 'altServer' DESC 'RFC2252: alternative servers' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 USAGE dSAOperation )
attributetype ( 2.5.18.10 NAME 'subschemaSubentry' DESC 'RFC2252: name of controlling subschema entry' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.9 NAME 'hasSubordinates' DESC 'X.501: entry has children' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.4 NAME 'modifiersName' DESC 'RFC2252: name of last modifier' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.3 NAME 'creatorsName' DESC 'RFC2252: name of creator' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.2 NAME 'modifyTimestamp' DESC 'RFC2252: time which object was last modified' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.1 NAME 'createTimestamp' DESC 'RFC2252: time which object was created' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.21.9 NAME 'structuralObjectClass' DESC 'X.500(93): structural object class of entry' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.4.0 NAME 'objectClass' DESC 'RFC2256: object classes of the entity' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
# These ones aren't published by OpenLDAP, but are referenced by the 'subschema' objectclass
attributetype ( 2.5.21.1 NAME 'dITStructureRules' EQUALITY integerFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.17 USAGE directoryOperation )
attributetype ( 2.5.21.7 NAME 'nameForms' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.35 USAGE directoryOperation )
attributetype ( 2.5.21.2 NAME 'dITContentRules' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.16 USAGE directoryOperation )

objectclass ( 2.5.20.1 NAME 'subschema' DESC 'RFC2252: controlling subschema (sub)entry' AUXILIARY MAY ( dITStructureRules $ nameForms $ ditContentRules $ objectClasses $ attributeTypes $ matchingRules $ matchingRuleUse ) )
#Don't have definition for subtreeSpecification:
#objectClass ( 2.5.17.0 NAME 'subentry' SUP top STRUCTURAL MUST ( cn $ subtreeSpecification ) )
objectClass ( 1.3.6.1.4.1.4203.1.4.1 NAME ( 'OpenLDAProotDSE' 'LDAProotDSE' ) DESC 'OpenLDAP Root DSE object' SUP top STRUCTURAL MAY cn )
objectClass ( 2.16.840.1.113730.3.2.6 NAME 'referral' DESC 'namedref: named subordinate referral' SUP top STRUCTURAL MUST ref )
objectClass ( 2.5.6.1 NAME 'alias' DESC 'RFC2256: an alias' SUP top STRUCTURAL MUST aliasedObjectName )
objectClass ( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' DESC 'RFC2252: extensible object' SUP top AUXILIARY )
objectClass ( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )
EOS
    end

    # After loading object classes and attr types: resolve oid strings to point
    # to objects. This will expose schema inconsistencies (e.g. objectclass
    # has unknown SUP class or points to unknown attributeType). However,
    # unknown Syntaxes just create new Syntax objects.

    def resolve_oids

      all_attrtypes.each do |a|
        if a.sup
          s = find_attrtype(a.sup)
          a.instance_eval {
            @sup = s
            # inherit properties (FIXME: This breaks to_def)
            @equality ||= s.equality
            @ordering ||= s.ordering
            @substr ||= s.substr
            @syntax ||= s.syntax
            @maxlen ||= s.maxlen
            @singlevalue ||= s.singlevalue
            @collective ||= s.collective
            @nousermod ||= s.nousermod
            @usage ||= s.usage
          }
        end
        a.instance_eval do
          @syntax = LDAP::Server::Syntax.find(@syntax) if @syntax
          @equality = LDAP::Server::MatchingRule.find(@equality) if @equality
          @ordering = LDAP::Server::MatchingRule.find(@ordering) if @ordering
          @substr = LDAP::Server::MatchingRule.find(@substr) if @substr
        end
      end

      all_objectclasses.each do |o|
        if o.sup
          s = o.sup.collect { |ss| find_objectclass(ss) }
          o.instance_eval { @sup = s }
        end
        if o.must
          s = o.must.collect { |ss| find_attrtype(ss) }
          o.instance_eval { @must = s }
        end
        if o.may
          s = o.may.collect { |ss| find_attrtype(ss) }
          o.instance_eval { @may = s }
        end
      end

    end

    # Validate a new entry or update. For a new entry, just pass a hash
    # of attr=>[val, val, ...]; for an update, the first parameter is
    # a hash of attr=>[:modtype, val, val...] and the second parameter
    # is the existing entry, where it is assumed that the attribute names
    # are already in their standard string forms (as returned by attr#name)
    #
    # Returns a hash containing the updated entry.
    #
    # If a block is given, it is called to decide whether the user is
    # allowed to update an attribute; parameter is the attr *object*
    # (not name; use #name if you need its name instead). Return false
    # if the update is not permitted. Otherwise, the only restriction
    # will be that updates to attributes declared 'nousermod' are forbidden.
    #
    # No DN checks are done here, since we don't know the DN.
    # Checking that the entry contains an attribute for the RDN is the
    # responsibility of the caller.

    def validate(mods, entry={})

      # Run through the mods, make the normalized names, and perform any
      # updates

      # FIXME: I don't know if these are the right results to return
      # for the various types of validation errors

      oc_changed = false
      res = entry.dup
      mods.each do |attrname, nv|
        attr = find_attrtype(attrname)
        attrname = attr.to_s
        raise LDAP::ResultError::ConstraintViolation,
          "Cannot modify #{attrname}" if attr.nousermod or
                                     (block_given? and !yield(attr))
        # Perform the update
        vals = res[attrname] || []
        checkvals = []
        nv = [nv] unless nv.is_a?(Array)

        case nv.first
        when :add
          checkvals = nv[1..-1]
          vals += checkvals
          vals.uniq!   # FIXME: ?? error if duplicate values
          # FIXME: normalize values? e.g. c: gb and c: GB are same value.
        when :delete
          nv = nv[1..-1]
          if nv.empty?
            vals = [] # ?? error if does not exist
          else
            nv.each { |v| vals.delete(v) } # ?? error if value missing
          end
        when :replace
          vals = checkvals = nv[1..-1]
        else
          vals = checkvals = nv
        end
        if vals == []
          res.delete(attrname)
        else
          res[attrname] = vals
        end

        # Attribute validation
        raise LDAP::ResultError::ObjectClassViolation,
          "Attribute #{attr} is SINGLE-VALUE" if attr.singlevalue and vals.size > 1

        checkvals.each do |val|
          raise LDAP::ResultError::InvalidAttributeSyntax,
            "Nil or empty value for attribute #{attr}" if val.nil? or val.empty?
          raise LDAP::ResultError::InvalidAttributeSyntax,
            "Bad value for #{attr}: #{val.inspect}" if attr.syntax and ! attr.syntax.match(val)
          raise LDAP::ResultError::InvalidAttributeSyntax,
            "Value too long for #{attr} (max #{attr.maxlen})" if attr.maxlen and val.length > attr.maxlen
        end

        oc_changed = true if attrname == 'objectClass'
      end

      # Now do objectClass checks
      oc = res['objectClass']
      unless oc
        raise LDAP::ResultError::ObjectClassViolation,
          "objectClass attribute missing"
      end
      oc = oc.collect { |val| find_objectclass(val) }

      if oc_changed
        # Add superior objectClasses (note: growing an array while you
        # iterate over it seems to work, in ruby-1.8.2 anyway!)
        oc.each do |objectclass|
          objectclass.sup.each do |s|
            oc.push(s) unless oc.include?(s)
          end
        end
        res['objectClass'] = oc.collect { |oo| oo.to_s }

        # Check that exactly one structural objectClass is present
        unless oc.find_all { |s| s.struct == :structural }.size >= 1
          raise LDAP::ResultError::ObjectClassViolation,
            "Entry must have at least one structural objectClass"
            # Exactly one? But you have to sort out the inheritance problem
            # (e.g. both person and organizationalPerson are declared
            # structural)
        end
      end

      # Ensure that all MUST attributes are present
      allow_attr = {}
      oc.each do |objectclass|
        objectclass.must.each do |m|
          unless res[m.name] and res[m.name] != []
            raise LDAP::ResultError::ObjectClassViolation, "Missing attribute #{m} required by objectClass #{objectclass}"
          end
          allow_attr[m.name] = true
        end
        objectclass.may.each do |m|
          allow_attr[m.name] = true
        end
      end

      unless oc.find { |objectclass| objectclass.name == 'extensibleObject' }
        # Now check all the attributes given are permitted by MUST or MAY
        res.each_key do |attr|
          unless allow_attr[attr] or find_attrtype(attr).usage == :directoryOperation
            raise LDAP::ResultError::ObjectClassViolation, "Attribute #{attr} not permitted by objectClass"
          end
        end
      end

      return res
    end

    # Hopefully backwards-compatible API for ruby-ldap's LDAP::Schema.
    # Since MUST/MAY/SUP may point to schema objects, convert them back
    # to strings.

    def names(key)
      case key
      when 'objectClasses'
        return all_objectclasses.collect { |e| e.name }
      when 'attributeTypes'
        return all_attrtypes.collect { |e| e.name }
      when 'ldapSyntaxes'
        return LDAP::Server::Syntax.all_syntaxes.collect { |e| e.name }
      when 'matchingRules'
        return LDAP::Server::MatchingRule.all_matching_rules.collect { |e| e.name }
      # TODO: matchingRuleUse
      end
      return nil
    end

    # Backwards-compatible for ruby-ldap LDAP::Schema

    def attr(oc,at)
      o = find_objectclass(oc)
      case at.upcase
      when 'MUST'
        return o.must.collect { |e| e.to_s }
      when 'MAY'
        return o.may.collect { |e| e.to_s }
      when 'SUP'
        return o.sup.collect { |e| e.to_s }
      when 'NAME'
        return o.names.collect { |e| e.to_s }
      when 'DESC'
        return [o.desc]
      end
      return nil
    rescue LDAP::ResultError
      return nil
    end

    # Backwards-compatible for ruby-ldap LDAP::Schema

    def must(oc)
      attr(oc, "MUST")
    end

    # Backwards-compatible for ruby-ldap LDAP::Schema

    def may(oc)
      attr(oc, "MAY")
    end

    # Backwards-compatible for ruby-ldap LDAP::Schema

    def sup(oc)
      attr(oc, "SUP")
    end

    #####################################################################

    # Class holding an instance of an AttributeTypeDescription (RFC2252 4.2)

    class AttributeType

      attr_reader :oid, :names, :desc, :obsolete, :sup, :equality, :ordering
      attr_reader :substr, :syntax, :maxlen, :singlevalue, :collective
      attr_reader :nousermod, :usage

      def initialize(str)
        m = LDAP::Server::Syntax::AttributeTypeDescription.match(str)
        raise LDAP::ResultError::InvalidAttributeSyntax,
          "Bad AttributeTypeDescription #{str.inspect}" unless m
        @oid = m[1]
        @names = (m[2]||"").scan(/'(.*?)'/).flatten
	@desc = m[3]
	@obsolete = ! m[4].nil?
	@sup = m[5]
	@equality = m[6]
	@ordering = m[7]
	@substr = m[8]
	@syntax = m[9]
	@maxlen = m[10] && m[10].to_i
	@singlevalue = ! m[11].nil?
	@collective = ! m[12].nil?
	@nousermod = ! m[13].nil?
	@usage = m[14] && m[14].intern
        # This is the cache of the stringified version. Rather than
        # initialize to str, we set nil to force it to be rebuilt
        @def = nil
      end

      def name
        @names.first
      end

      def to_s
        (@names && @names.first) || @oid
      end

      def changed
        @def = nil
      end

      def to_def
        return @def if @def
        ans = "( #{@oid} "
        if @names.nil? or @names.empty?
          # nothing
        elsif @names.size == 1
          ans << "NAME '#{@names.first}' "
        else
          ans << "NAME ( "
          @names.each { |n| ans << "'#{n}' " }
          ans << ") "
        end
        ans << "DESC '#{@desc}' " if @desc
        ans << "OBSOLETE " if @obsolete
        ans << "SUP #{@sup} " if @sup			# oid
        ans << "EQUALITY #{@equality} " if @equality	# oid
        ans << "ORDERING #{@ordering} " if @ordering	# oid
        ans << "SUBSTR #{@substr} " if @substr		# oid
        ans << "SYNTAX #{@syntax}#{@maxlen && "{#{@maxlen}}"} " if @syntax
        ans << "SINGLE-VALUE " if @singlevalue
        ans << "COLLECTIVE " if @collective
        ans << "NO-USER-MODIFICATION " if @nousermod
        ans << "USAGE #{@usage} " if @usage
        ans << ")"
        @def = ans
      end
    end # class AttributeType

    #####################################################################

    # Class holding an instance of an ObjectClassDescription (RFC2252 4.4)

    class ObjectClass

      attr_reader :oid, :names, :desc, :obsolete, :sup, :struct, :must, :may

      SCAN_WOID = /#{LDAP::Server::Syntax::WOID}/x

      def initialize(str)
        m = LDAP::Server::Syntax::ObjectClassDescription.match(str)
        raise LDAP::ResultError::InvalidAttributeSyntax,
          "Bad ObjectClassDescription #{str.inspect}" unless m
        @oid = m[1]
        @names = (m[2]||"").scan(/'(.*?)'/).flatten
	@desc = m[3]
	@obsolete = ! m[4].nil?
	@sup = (m[5]||"").scan(SCAN_WOID).flatten
        @struct = m[6] ? m[6].downcase.intern : :structural
        @must = (m[7]||"").scan(SCAN_WOID).flatten
        @may = (m[8]||"").scan(SCAN_WOID).flatten
        @def = nil
      end

      def name
        @names.first
      end

      def to_s
        (@names && @names.first) || @oid
      end

      def changed
        @def = nil
      end

      def to_def
        return @def if @def
        ans = "( #{@oid} "
        if @names.nil? or @names.empty?
          # nothing
        elsif @names.size == 1
          ans << "NAME '#{@names.first}' "
        else
          ans << "NAME ( "
          @names.each { |n| ans << "'#{n}' " }
          ans << ") "
        end
        ans << "DESC '#{@desc}' " if @desc
        ans << "OBSOLETE " if @obsolete
        ans << joinoids("SUP ",@sup," ")
        ans << "#{@struct.to_s.upcase} " if @struct
        ans << joinoids("MUST ",@must," ")
        ans << joinoids("MAY ",@may," ")
        ans << ")"
        @def = ans
      end

      def joinoids(pfx,arr,sfx)
        return "" unless arr and !arr.empty?
        return "#{pfx}#{arr}#{sfx}" unless arr.is_a?(Array)
        a = arr.collect { |elem| elem.to_s }
        if a.size == 1
          return "#{pfx}#{a.first}#{sfx}"
        else
          return "#{pfx}( #{a.join(" $ ")} )#{sfx}"
        end
      end
    end # class ObjectClass

  end # class Schema

end # class Server
end # module LDAP
