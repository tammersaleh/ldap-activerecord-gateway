module LDAP
class Server

  # A class which describes LDAP SyntaxDescriptions. For now there is
  # a global pool of Syntax objects (rather than each Schema object
  # having its own set)

  class Syntax
    attr_reader :oid, :nhr, :binary, :desc

    # Create a new Syntax object

    def initialize(oid, desc=nil, opt={}, &blk)
      @oid = oid
      @desc = desc
      @nhr = opt[:nhr]		# not human-readable?
      @binary = opt[:binary]	# binary encoding forced?
      @re = opt[:re]		# regular expression for parsing
      @def = nil
      instance_eval(&blk) if blk
    end

    def to_s
      @oid
    end

    # Create a new Syntax object, given its description string

    def self.from_def(str, &blk)
      m = LDAPSyntaxDescription.match(str)
      raise LDAP::ResultError::InvalidAttributeSyntax,
        "Bad SyntaxTypeDescription #{str.inspect}" unless m
      new(m[1], m[2], :nhr=>(m[3] == 'TRUE'), :binary=>(m[4] == 'TRUE'), &blk)
    end

    # Convert this object to its description string

    def to_def
      return @def if @def
      ans = "( #@oid "
      ans << "DESC '#@desc' " if @desc
      # These are OpenLDAP extensions
      ans << "X-BINARY-TRANSFER-REQUIRED 'TRUE' " if @binary
      ans << "X-NOT-HUMAN-READABLE 'TRUE' " if @nhr
      ans << ")"
      @def = ans
    end

    # Return true or a MatchData object if the given value is allowed
    # by this syntax

    def match(val)
      return true if @re.nil?
      @re.match(value_to_s(val))
    end

    # Convert a value for this syntax into its canonical string representation
    # (not yet used, but seemed like a good idea)

    def value_to_s(val)
      val.to_s
    end

    # Convert a string value for this syntax into a Ruby-like value
    # (not yet used, but seemed like a good idea)

    def value_from_s(val)
      val
    end

    @@syntaxes = {}

    # Add a new syntax definition

    def self.add(*args, &blk)
      s = new(*args, &blk)
      @@syntaxes[s.oid] = s
    end

    # Find a Syntax object given an oid. If not known, return a new empty
    # Syntax object associated with this oid.

    def self.find(oid)
      return oid if oid.nil? or oid.is_a?(LDAP::Server::Syntax)
      return @@syntaxes[oid] if @@syntaxes[oid]
      add(oid)
    end

    # Return all known syntax objects

    def self.all_syntaxes
      @@syntaxes.values.uniq
    end

    # Shared constants for regexp-based syntax parsers

    KEYSTR = "[a-zA-Z][a-zA-Z0-9;-]*"
    NUMERICOID = "( \\d[\\d.]+\\d )"
    WOID = "\\s* ( #{KEYSTR} | \\d[\\d.]+\\d ) \\s*"
    _WOID = "\\s* (?: #{KEYSTR} | \\d[\\d.]+\\d ) \\s*"
    OIDS = "( #{_WOID} | \\s* \\( #{_WOID} (?: \\$ #{_WOID} )* \\) \\s* )"
    _QDESCR = "\\s* ' #{KEYSTR} ' \\s*"
    QDESCRS = "( #{_QDESCR} | \\s* \\( (?:#{_QDESCR})+ \\) \\s* )"
    QDSTRING = "\\s* ' (.*?) ' \\s*"
    NOIDLEN = "(\\d[\\d.]+\\d) (?: \\{ (\\d+) \\} )?"
    ATTRIBUTEUSAGE = "(userApplications|directoryOperation|distributedOperation|dSAOperation)"

  end

  class Syntax

    # These are the 'SHOULD' support syntaxes from RFC2252 section 6

    AttributeTypeDescription =
    add("1.3.6.1.4.1.1466.115.121.1.3", "Attribute Type Description", :re=>
    %r! \A \s* \( \s*
	    #{NUMERICOID} \s*
	(?: NAME #{QDESCRS} )?
	(?: DESC #{QDSTRING} )?
	(   OBSOLETE \s* )?
	(?: SUP #{WOID} )?
	(?: EQUALITY #{WOID} )?
	(?: ORDERING #{WOID} )?
	(?: SUBSTR #{WOID} )?
	(?: SYNTAX \s* #{NOIDLEN} \s* )?	# capture 2
	(   SINGLE-VALUE \s* )?
	(   COLLECTIVE \s* )?
	(   NO-USER-MODIFICATION \s* )?
	(?: USAGE \s* #{ATTRIBUTEUSAGE} )?
    \s* \) \s* \z !xu)

    add("1.3.6.1.4.1.1466.115.121.1.5", "Binary", :nhr=>true)
    # FIXME: value_to_s should BER-encode the value??

    add("1.3.6.1.4.1.1466.115.121.1.6", "Bit String", :re=>/\A'([01]*)'B\z/)
    # FIXME: convert to FixNum?

    add("1.3.6.1.4.1.1466.115.121.1.7", "Boolean", :re=>/\A(TRUE|FALSE)\z/) do
      def self.value_to_s(v)
        return v if v.is_a?(string)
        v ? "TRUE" : "FALSE"
      end
      def self.value_from_s(v)
        v.upcase == "TRUE"
      end
    end

    add("1.3.6.1.4.1.1466.115.121.1.8", "Certificate", :binary=>true, :nhr=>true)
    add("1.3.6.1.4.1.1466.115.121.1.9", "Certificate List", :binary=>true, :nhr=>true)
    add("1.3.6.1.4.1.1466.115.121.1.10", "Certificate Pair", :binary=>true, :nhr=>true)
    add("1.3.6.1.4.1.1466.115.121.1.11", "Country String", :re=>/\A[A-Z]{2}\z/i)
    add("1.3.6.1.4.1.1466.115.121.1.12", "Distinguished Name")
    # FIXME: validate DN?
    add("1.3.6.1.4.1.1466.115.121.1.15", "Directory String")
    # missed due to lack of interest: "DIT Content Rule Description"
    add("1.3.6.1.4.1.1466.115.121.1.22", "Facsimile Telephone Number")
    add(" 1.3.6.1.4.1.1466.115.121.1.23", "Fax", :nhr=>true)
    add("1.3.6.1.4.1.1466.115.121.1.24", "Generalized Time")
    # FIXME: Validate Generalized Time (find X.208) and convert to/from Ruby Time
    add("1.3.6.1.4.1.1466.115.121.1.26", "IA5 String")
    add("1.3.6.1.4.1.1466.115.121.1.27", "Integer", :re=>/\A\d+\z/) do
      def self.value_from_s(v)
        v.to_i
      end
    end
    add("1.3.6.1.4.1.1466.115.121.1.28", "JPEG", :nhr=>true)
    MatchingRuleDescription =
    add("1.3.6.1.4.1.1466.115.121.1.30", "Matching Rule Description", :re=>
    %r! \A \s* \( \s*
	    #{NUMERICOID} \s*
	(?: NAME #{QDESCRS} )?
	(?: DESC #{QDSTRING} )?
	(   OBSOLETE \s* )?
	    SYNTAX \s* #{NUMERICOID} \s*
    \s* \) \s* \z !xu)
    MatchingRuleUseDescription =
    add("1.3.6.1.4.1.1466.115.121.1.31", "Matching Rule Use Description", :re=>
    %r! \A \s* \( \s*
	    #{NUMERICOID} \s*
	(?: NAME #{QDESCRS} )?
	(?: DESC #{QDSTRING} )?
	(   OBSOLETE \s* )?
	    APPLIES \s* #{OIDS} \s*
    \s* \) \s* \z !xu)
    add("1.3.6.1.4.1.1466.115.121.1.33", "MHS OR Address")
    add("1.3.6.1.4.1.1466.115.121.1.34", "Name And Optional UID")
    # missed due to lack of interest: "Name Form Description"
    add("1.3.6.1.4.1.1466.115.121.1.36", "Numeric String", :re=>/\A\d+\z/)
    ObjectClassDescription =
    add("1.3.6.1.4.1.1466.115.121.1.37", "Object Class Description", :re=>
    %r! \A \s* \( \s*
	#{NUMERICOID} \s*
	(?: NAME #{QDESCRS} )?
	(?: DESC #{QDSTRING} )?
	(   OBSOLETE \s* )?
	(?: SUP #{OIDS} )?
	(?: ( ABSTRACT|STRUCTURAL|AUXILIARY ) \s* )?
	(?: MUST #{OIDS} )?
	(?: MAY #{OIDS} )?
    \s* \) \s* \z !xu)
    add("1.3.6.1.4.1.1466.115.121.1.38", "OID", :re=>/\A#{WOID}\z/xu)
    add("1.3.6.1.4.1.1466.115.121.1.39", "Other Mailbox")
    add("1.3.6.1.4.1.1466.115.121.1.41", "Postal Address") do
      def self.value_from_s(v)
        v.split(/\$/)
      end
      def self.value_to_s(v)
        return v.join("$") if v.is_a?(Array)
        return v
      end
    end
    add("1.3.6.1.4.1.1466.115.121.1.43", "Presentation Address")
    add("1.3.6.1.4.1.1466.115.121.1.44", "Printable String")
    add("1.3.6.1.4.1.1466.115.121.1.50", "Telephone Number")
    add("1.3.6.1.4.1.1466.115.121.1.53", "UTC Time")

    LDAPSyntaxDescription =
    add("1.3.6.1.4.1.1466.115.121.1.54", "LDAP Syntax Description", :re=>
    %r! \A \s* \( \s*
	    #{NUMERICOID} \s*
	(?: DESC #{QDSTRING} )?
	(?: X-BINARY-TRANSFER-REQUIRED \s* ' (TRUE|FALSE) ' \s* )?
	(?: X-NOT-HUMAN-READABLE \s* ' (TRUE|FALSE) ' \s* )?
    \s* \) \s* \z !xu)

    # Missed due to lack of interest: "DIT Structure Rule Description"

    # A few others from RFC2252 section 4.3.2
    add("1.3.6.1.4.1.1466.115.121.1.4", "Audio", :nhr=>true)
    add("1.3.6.1.4.1.1466.115.121.1.40", "Octet String")
    add("1.3.6.1.4.1.1466.115.121.1.58", "Substring Assertion")
  end
    
end # class Server
end # module LDAP
