require 'ldap/server/result'
require 'ldap/server/match'

module LDAP
class Server

  # LDAP filters are parsed into a LISP-like internal representation:
  #
  #   [:true]
  #   [:false]
  #   [:undef]
  #   [:and, ..., ..., ...]
  #   [:or, ..., ..., ...]
  #   [:not, ...]
  #   [:present, attr]
  #   [:eq, attr, MO, val]
  #   [:approx, attr, MO, val]
  #   [:substrings, attr, MO, initial=nil, {any, any...}, final=nil]
  #   [:ge, attr, MO, val]
  #   [:le, attr, MO, val]
  #
  # This is done rather than a more object-oriented approach, in the
  # hope that it will make it easier to match certain filter structures
  # when converting them into something else. e.g. certain LDAP filter
  # constructs can be mapped to some fixed SQL queries.
  #
  # See RFC 2251 4.5.1 for the three-state(!) boolean logic from LDAP
  #
  # If no schema is provided: 'attr' is the raw attribute name as provided
  # by the client. If a schema is provided: attr is converted to its
  # normalized name as listed in the schema, e.g. 'commonname' becomes 'cn',
  # 'objectclass' becomes 'objectClass' etc.
  # If a schema is provided, MO is a matching object which can be used to
  # perform the match. If no schema is provided, this is 'nil'. In that
  # case you could use LDAP::Server::MatchingRule::DefaultMatch.

  class Filter

    # Parse a filter in OpenSSL::ASN1 format into our own format.
    #
    # There are some trivial optimisations we make: e.g.
    #   (&(objectClass=*)(cn=foo)) -> (&(cn=foo)) -> (cn=foo)

    def self.parse(asn1, schema=nil)
      case asn1.tag
      when 0 # and
        conds = asn1.value.collect { |a| parse(a) }
        conds.delete([:true])
        return [:true] if conds.size == 0
        return conds.first if conds.size == 1
        return [:false] if conds.include?([:false])
        return conds.unshift(:and)

      when 1 # or
        conds = asn1.value.collect { |a| parse(a) }
        conds.delete([:false])
        return [:false] if conds.size == 0
        return conds.first if conds.size == 1
        return [:true] if conds.include?([:true])
        return conds.unshift(:or)

      when 2 # not
        cond = parse(asn1.value[0])
        case cond
        when [:false];	return [:true]
	when [:true];	return [:false]
	when [:undef];	return [:undef]
	end
	return [:not, cond]

      when 3 # equalityMatch
        attr = asn1.value[0].value
        val = asn1.value[1].value
        return [:true] if attr =~ /\AobjectClass\z/i and val =~ /\Atop\z/i
        if schema
          a = schema.find_attrtype(attr)
          return [:undef] unless a.equality
          return [:eq, a.to_s, a.equality, val]
        end
        return [:eq, attr, nil, val]

      when 4 # substrings
        attr = asn1.value[0].value
        if schema
          a = schema.find_attrtype(attr)
          return [:undef] unless a.substr
          res = [:substrings, a.to_s, a.substr, nil]
        else
          res = [:substrings, attr, nil, nil]
        end
        final_val = nil

        asn1.value[1].value.each do |ss|
          case ss.tag
          when 0
            res[3] = ss.value
          when 1
            res << ss.value
          when 2
            final_val = ss.value
          else
            raise LDAP::ResultError::ProtocolError,
              "Unrecognised substring tag #{ss.tag.inspect}"
          end
        end
        res << final_val
        return res

      when 5 # greaterOrEqual
        attr = asn1.value[0].value
        val = asn1.value[1].value
        if schema
          a = schema.find_attrtype(attr)
          return [:undef] unless a.ordering
          return [:ge, a.to_s, a.ordering, val]
        end
        return [:ge, attr, nil, val]

      when 6 # lessOrEqual
        attr = asn1.value[0].value
        val = asn1.value[1].value
        if schema
          a = schema.find_attrtype(attr)
          return [:undef] unless a.ordering
          return [:le, a.to_s, a.ordering, val]
        end
        return [:le, attr, nil, val]

      when 7 # present
        attr = asn1.value
        return [:true] if attr =~ /\AobjectClass\z/i
        if schema
          begin
            a = schema.find_attrtype(attr)
            return [:present, a.to_s]
          rescue LDAP::ResultError::UndefinedAttributeType
            return [:false]
          end
        end
        return [:present, attr]

      when 8 # approxMatch
        attr = asn1.value[0].value
        val = asn1.value[1].value
        if schema
          a = schema.find_attrtype(attr)
          # I don't know how properly to deal with approxMatch. I'm assuming
          # that the object will have an equality MatchingRule, and we
          # can defer to that.
          return [:undef] unless a.equality
          return [:approx, a.to_s, a.equality, val]
        end
        return [:approx, attr, nil, val]

      #when 9 # extensibleMatch
      #  FIXME

      else
        raise LDAP::ResultError::ProtocolError,
          "Unrecognised Filter tag #{asn1.tag}"
      end

    # Unknown attribute type
    rescue LDAP::ResultError::UndefinedAttributeType
      return [:undef]
    end

    # Run a parsed filter against an attr=>[val] hash.
    #
    # Returns true, false or nil.

    def self.run(filter, av)
      case filter[0]
      when :and
        res = true
        filter[1..-1].each do |elem|
          r = run(elem, av)
          return false if r == false
          res = nil if r.nil?
        end
        return res

      when :or
        res = false
        filter[1..-1].each do |elem|
          r = run(elem, av)
          return true if r == true
          res = nil if r.nil?
        end
        return res

      when :not
        case run(filter[1], av)
        when true; 	return false
        when false;	return true
        else		return nil
        end

      when :present
        return av.has_key?(filter[1])

      when :eq, :approx, :le, :ge, :substrings
        # the filter now includes a suitable matching object
        return (filter[2] || LDAP::Server::MatchingRule::DefaultMatch).send(
                filter.first, av[filter[1].to_s], *filter[3..-1])

      when :true
        return true

      when :false
        return false

      when :undef
        return nil
      end

      raise LDAP::ResultError::OperationsError,
        "Unimplemented filter #{filter.first.inspect}"
    end

  end # class Filter
end # class Server
end # module LDAP
