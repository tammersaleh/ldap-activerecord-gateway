require 'ldap/server/result'

module LDAP
class Server

  class Operation

    # Return true if connection is not authenticated

    def anonymous?
      @connection.binddn.nil?
    end

    # Split dn string into its component parts, returning
    #  [ {attr=>val}, {attr=>val}, ... ]
    #
    # This is pretty horrible legacy stuff from X500; see RFC2253 for the
    # full gore. It's stupid that the LDAP protocol sends the DN in string
    # form, rather than in ASN1 form (as it does with search filters, for
    # example), even though the DN syntax is defined in terms of ASN1!
    #
    # Attribute names are downcased, but values are not. For any
    # case-insensitive attributes it's up to you to downcase them.
    #
    # Note that only v2 clients should add extra space around the comma.
    # This is accepted, and so is semicolon instead of comma, but the
    # full RFC1779 backwards-compatibility rules (e.g. quoted values)
    # are not implemented.
    #
    # I *think* these functions will work correctly with UTF8-encoded
    # characters, given that a multibyte UTF8 character does not contain
    # the bytes 00-7F and therefore we cannot confuse '\', '+' etc

    def self.split_dn(dn)
      # convert \\ to \5c, \+ to \2b etc
      dn2 = dn.gsub(/\\([ #,+"\\<>;])/) { "\\%02x" % $1[0] }

      # Now we know that \\ and \, do not exist, it's safe to split
      parts = dn2.split(/\s*[,;]\s*/)

      parts.collect do |part|
        res = {}

        # Split each part into attr=val+attr=val
        avs = part.split(/\+/)

        avs.each do |av|
          # These should all be of form attr=value
          unless av =~ /^([^=]+)=(.*)$/
            raise LDAP::ResultError::ProtocolError, "Bad DN component: #{av}"
          end
          attr, val = $1.downcase, $2
          # Now we can decode those bits
          attr.gsub!(/\\([a-f0-9][a-f0-9])/i) { $1.hex.chr }
          val.gsub!(/\\([a-f0-9][a-f0-9])/i) { $1.hex.chr }
          res[attr] = val
        end
        res
      end
    end

    # Reverse of split_dn. Join [elements...]
    # where each element can be {attr=>val,...} or [[attr,val],...]
    # or just [attr,val]

    def self.join_dn(elements)
      dn = ""
      elements.each do |elem|
        av = ""
        elem = [elem] if elem[0].is_a?(String)
        elem.each do |attr,val|
          av << "+" unless av == ""

          av << attr << "=" <<
                     val.sub(/^([# ])/, '\\\\\\1').
                     sub(/( )$/, '\\\\\\1').
                     gsub(/([,+"\\<>;])/, '\\\\\\1')
        end
        dn << "," unless dn == ""
        dn << av
      end
      dn
    end

  end # class Operation

end # class Server
end # module LDAP
