require 'timeout'
require 'ldap/server/result'
require 'ldap/server/filter'

module LDAP
class Server

  # Scope
  BaseObject		= 0
  SingleLevel		= 1
  WholeSubtree		= 2

  # DerefAliases
  NeverDerefAliases	= 0
  DerefInSearching	= 1
  DerefFindingBaseObj	= 2
  DerefAlways		= 3

  # Object to handle a single LDAP request. Typically you would
  # subclass this object and override methods 'simple_bind', 'search' etc.
  # The do_xxx methods are internal, and handle the parsing of requests
  # and the sending of responses.

  class Operation

    # An instance of this object is created by the Connection object
    # for each operation which is requested by the client. If you subclass
    # Operation, and you override initialize, make sure you call 'super'.

    def initialize(connection, messageID)
      @connection = connection
      @respEnvelope = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Integer(messageID),
        # protocolOp,
        # controls [0] OPTIONAL,
      ])
      @schema = @connection.opt[:schema]
      @server = @connection.opt[:server]
    end

    # Send a log message

    def log(*args)
      @connection.log(*args)
    end

    # Send an exception report to the log

    def log_exception(e)
      @connection.log "#{e}: #{e.backtrace.join("\n\tfrom ")}"
    end

    ##################################################
    ### Utility methods to send protocol responses ###
    ##################################################

    def send_LDAPMessage(protocolOp, opt={}) # :nodoc:
      @respEnvelope.value[1] = protocolOp
      if opt[:controls]
        @respEnvelope.value[2] = OpenSSL::ASN1::Set(opt[:controls], 0, :IMPLICIT, APPLICATION)
      else
        @respEnvelope.value.delete_at(2)
      end

      if false # $debug
        puts "Response:"
        p @respEnvelope
        p @respEnvelope.to_der.unpack("H*")
      end

      @connection.write(@respEnvelope.to_der)
    end

    def send_LDAPResult(tag, resultCode, opt={}) # :nodoc:
      seq = [
        OpenSSL::ASN1::Enumerated(resultCode),
        OpenSSL::ASN1::OctetString(opt[:matchedDN] || ""),
        OpenSSL::ASN1::OctetString(opt[:errorMessage] || ""),
      ]
      if opt[:referral]
        rs = opt[:referral].collect { |r| OpenSSL::ASN1::OctetString(r) }
        seq << OpenSSL::ASN1::Sequence(rs, 3, :IMPLICIT, :APPLICATION)
      end
      yield seq if block_given?   # opportunity to add more elements
        
      send_LDAPMessage(OpenSSL::ASN1::Sequence(seq, tag, :IMPLICIT, :APPLICATION), opt)
    end

    def send_BindResponse(resultCode, opt={})
      send_LDAPResult(1, resultCode, opt) do |resp|
        if opt[:serverSaslCreds]
          resp << OpenSSL::ASN1::OctetString(opt[:serverSaslCreds], 7, :IMPLICIT, :APPLICATION)
        end
      end
    end

    # Send a found entry. Avs are {attr1=>val1, attr2=>[val2,val3]}
    # If schema given, return operational attributes only if
    # explicitly requested

    def send_SearchResultEntry(dn, avs, opt={})
      @rescount += 1
      if @sizelimit
        raise LDAP::ResultError::SizeLimitExceeded if @rescount > @sizelimit
      end

      if @schema
        # normalize the attribute names
        @attributes = @attributes.collect { |a| @schema.find_attrtype(a).to_s }
      end

      sendall = @attributes == [] || @attributes.include?("*")
      avseq = []

      avs.each do |attr, vals|
        if !@attributes.include?(attr)
          next unless sendall
          if @schema
            a = @schema.find_attrtype(attr)
            next unless a and (a.usage.nil? or a.usage == :userApplications)
          end
        end

        if @typesOnly
          vals = [] 
        else
          vals = [vals] unless vals.kind_of?(Array)
          # FIXME: optionally do a value_to_s conversion here?
          # FIXME: handle attribute;binary
        end

        avseq << OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::OctetString(attr),
          OpenSSL::ASN1::Set(vals.collect { |v| OpenSSL::ASN1::OctetString(v.to_s) })
        ])
      end

      send_LDAPMessage(OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::OctetString(dn),
          OpenSSL::ASN1::Sequence(avseq),
        ], 4, :IMPLICIT, :APPLICATION), opt)
    end

    def send_SearchResultReference(urls, opt={})
      send_LDAPMessage(OpenSSL::ASN1::Sequence(
          urls.collect { |url| OpenSSL::ASN1::OctetString(url) }
        ),
        opt
      )
    end

    def send_SearchResultDone(resultCode, opt={})
      send_LDAPResult(5, resultCode, opt)
    end

    def send_ModifyResponse(resultCode, opt={})
      send_LDAPResult(7, resultCode, opt)
    end

    def send_AddResponse(resultCode, opt={})
      send_LDAPResult(9, resultCode, opt)
    end

    def send_DelResponse(resultCode, opt={})
      send_LDAPResult(11, resultCode, opt)
    end

    def send_ModifyDNResponse(resultCode, opt={})
      send_LDAPResult(13, resultCode, opt)
    end

    def send_CompareResponse(resultCode, opt={})
      send_LDAPResult(15, resultCode, opt)
    end

    def send_ExtendedResponse(resultCode, opt={})
      send_LDAPResult(24, resultCode, opt) do |resp|
        if opt[:responseName]
          resp << OpenSSL::ASN1::OctetString(opt[:responseName], 10, :IMPLICIT, :APPLICATION)
        end
        if opt[:response]
          resp << OpenSSL::ASN1::OctetString(opt[:response], 11, :IMPLICIT, :APPLICATION)
        end
      end
    end

    ##########################################
    ### Methods to parse each request type ###
    ##########################################

    def do_bind(protocolOp, controls) # :nodoc:
      version = protocolOp.value[0].value
      dn = protocolOp.value[1].value
      dn = nil if dn == ""
      authentication = protocolOp.value[2]

      case authentication.tag   # tag_class == :CONTEXT_SPECIFIC (check why)
      when 0
        simple_bind(version, dn, authentication.value)
      when 3
        mechanism = authentication.value[0].value
        credentials = authentication.value[1].value
        # sasl_bind(version, dn, mechanism, credentials)
        # FIXME: needs to exchange further BindRequests
        raise LDAP::ResultError::AuthMethodNotSupported
      else
        raise LDAP::ResultError::ProtocolError, "BindRequest bad AuthenticationChoice"
      end
      send_BindResponse(0)
      return dn, version

    rescue LDAP::ResultError => e
      send_BindResponse(e.to_i, :errorMessage=>e.message)
      return nil, version
    end

    # reformat ASN1 into {attr=>[vals], attr=>[vals]}
    #
    #     AttributeList ::= SEQUENCE OF SEQUENCE {
    #            type    AttributeDescription,
    #            vals    SET OF AttributeValue }

    def attributelist(set) # :nodoc:
      av = {}
      set.value.each do |seq|
        a = seq.value[0].value
        if @schema
          a = @schema.find_attrtype(a).to_s
        end
        v = seq.value[1].value.collect { |asn1| asn1.value  }
        # Not clear from the spec whether the same attribute (with
        # distinct values) can appear more than once in AttributeList
        raise LDAP::ResultError::AttributeOrValueExists, a if av[a]
        av[a] = v
      end
      return av
    end

    def do_search(protocolOp, controls) # :nodoc:
      baseObject = protocolOp.value[0].value
      scope = protocolOp.value[1].value
      deref = protocolOp.value[2].value
      client_sizelimit = protocolOp.value[3].value
      client_timelimit = protocolOp.value[4].value
      @typesOnly = protocolOp.value[5].value
      filter = Filter::parse(protocolOp.value[6], @schema)
      @attributes = protocolOp.value[7].value.collect {|x| x.value}

      @rescount = 0
      @sizelimit = server_sizelimit
      @sizelimit = client_sizelimit if client_sizelimit > 0 and
                   (@sizelimit.nil? or client_sizelimit < @sizelimit)

      if baseObject.empty? and scope == BaseObject
        send_SearchResultEntry("", @server.root_dse) if
          @server.root_dse and LDAP::Server::Filter.run(filter, @server.root_dse)
        send_SearchResultDone(0)
        return
      elsif @schema and baseObject == @schema.subschema_dn
        send_SearchResultEntry(baseObject, @schema.subschema_subentry) if
          @schema and @schema.subschema_subentry and
          LDAP::Server::Filter.run(filter, @schema.subschema_subentry)
        send_SearchResultDone(0)
        return
      end

      t = server_timelimit || 10
      t = client_timelimit if client_timelimit > 0 and client_timelimit < t

      Timeout::timeout(t, LDAP::ResultError::TimeLimitExceeded) do
        search(baseObject, scope, deref, filter)
      end
      send_SearchResultDone(0)

    # Note that TimeLimitExceeded is a subclass of LDAP::ResultError
    rescue LDAP::ResultError => e
      send_SearchResultDone(e.to_i, :errorMessage=>e.message)

    rescue Abandon
      # send no response

    # Since this Operation is running in its own thread, we have to
    # catch all other exceptions. Otherwise, in the event of a programming
    # error, this thread will silently terminate and the client will wait
    # forever for a response.

    rescue Exception => e
      log_exception(e)
      send_SearchResultDone(LDAP::ResultError::OperationsError.new.to_i, :errorMessage=>e.message)
    end

    def do_modify(protocolOp, controls) # :nodoc:
      dn = protocolOp.value[0].value
      modinfo = {}
      protocolOp.value[1].value.each do |seq|
        attr = seq.value[1].value[0].value
        if @schema
          attr = @schema.find_attrtype(attr).to_s
        end
        vals = seq.value[1].value[1].value.collect { |v| v.value }
        case seq.value[0].value
        when 0
          modinfo[attr] = [:add] + vals
        when 1
          modinfo[attr] = [:delete] + vals
        when 2
          modinfo[attr] = [:replace] + vals
        else
          raise LDAP::ResultError::ProtocolError, "Bad modify operation #{seq.value[0].value}"
        end
      end

      modify(dn, modinfo)
      send_ModifyResponse(0)

    rescue LDAP::ResultError => e
      send_ModifyResponse(e.to_i, :errorMessage=>e.message)
    rescue Abandon
      # no response
    rescue Exception => e
      log_exception(e)
      send_ModifyResponse(LDAP::ResultCode::OperationsError.new.to_i, :errorMessage=>e.message)
    end

    def do_add(protocolOp, controls) # :nodoc:
      dn = protocolOp.value[0].value
      av = attributelist(protocolOp.value[1])
      add(dn, av)
      send_AddResponse(0)

    rescue LDAP::ResultError => e
      send_AddResponse(e.to_i, :errorMessage=>e.message)
    rescue Abandon
      # no response
    rescue Exception => e
      log_exception(e)
      send_AddResponse(LDAP::ResultCode::OperationsError.new.to_i, :errorMessage=>e.message)
    end

    def do_del(protocolOp, controls) # :nodoc:
      dn = protocolOp.value
      del(dn)
      send_DelResponse(0)

    rescue LDAP::ResultError => e
      send_DelResponse(e.to_i, :errorMessage=>e.message)
    rescue Abandon
      # no response
    rescue Exception => e
      log_exception(e)
      send_DelResponse(LDAP::ResultCode::OperationsError.new.to_i, :errorMessage=>e.message)
    end

    def do_modifydn(protocolOp, controls) # :nodoc:
      entry = protocolOp.value[0].value
      newrdn = protocolOp.value[1].value
      deleteoldrdn = protocolOp.value[2].value
      if protocolOp.value.size > 3 and protocolOp.value[3].tag == 0
        newSuperior = protocolOp.value[3].value
      end
      modifydn(entry, newrdn, deleteoldrdn, newSuperior)
      send_ModifyDNResponse(0)

    rescue LDAP::ResultError => e
      send_ModifyDNResponse(e.to_i, :errorMessage=>e.message)
    rescue Abandon
      # no response
    rescue Exception => e
      log_exception(e)
      send_ModifyDNResponse(LDAP::ResultCode::OperationsError.new.to_i, :errorMessage=>e.message)
    end

    def do_compare(protocolOp, controls) # :nodoc:
      entry = protocolOp.value[0].value
      ava = protocolOp.value[1].value
      attr = ava[0].value
      if @schema
        attr = @schema.find_attrtype(attr).to_s
      end
      val = ava[1].value
      if compare(entry, attr, val)
        send_CompareResponse(6)  # compareTrue
      else
        send_CompareResponse(5)  # compareFalse
      end

    rescue LDAP::ResultError => e
      send_CompareResponse(e.to_i, :errorMessage=>e.message)
    rescue Abandon
      # no response
    rescue Exception => e
      log_exception(e)
      send_CompareResponse(LDAP::ResultCode::OperationsError.new.to_i, :errorMessage=>e.message)
    end

    ############################################################
    ### Methods to get parameters related to this connection ###
    ############################################################

    # Server-set maximum time limit. Override for more complex behaviour
    # (e.g. limit depends on @connection.binddn). Nil uses hardcoded default.

    def server_timelimit
      @connection.opt[:timelimit]
    end

    # Server-set maximum size limit. Override for more complex behaviour
    # (e.g. limit depends on @connection.binddn). Return nil for unlimited.

    def server_sizelimit
      @connection.opt[:sizelimit]
    end

    ######################################################
    ### Methods to actually perform the work requested ###
    ######################################################

    # Handle a simple bind request; raise an exception if the bind is
    # not acceptable, otherwise just return to accept the bind.
    #
    # Override this method in your own subclass.

    def simple_bind(version, dn, password)
      if version != 3
        raise LDAP::ResultError::ProtocolError, "version 3 only"
      end
      if dn
        raise LDAP::ResultError::InappropriateAuthentication, "This server only supports anonymous bind"
      end
    end

    # Handle a search request; override this.
    #
    # Call send_SearchResultEntry for each result found. Raise an exception
    # if there is a problem. timeLimit, sizeLimit and typesOnly are taken
    # care of, but you need to perform all authorisation checks yourself,
    # using @connection.binddn

    def search(basedn, scope, deref, filter, attrs)
      raise LDAP::ResultError::UnwillingToPerform, "search not implemented"
    end

    # Handle a modify request; override this
    #
    # dn is the object to modify; modification is a hash of
    #   attr => [:add, val, val...]       -- add operation
    #   attr => [:replace, val, val...]   -- replace operation
    #   attr => [:delete, val, val...]    -- delete these values
    #   attr => [:delete]                 -- delete all values

    def modify(dn, modification)
      raise LDAP::ResultError::UnwillingToPerform, "modify not implemented"
    end

    # Handle an add request; override this
    #
    # Parameters are the dn of the entry to add, and a hash of
    #   attr=>[val...]
    # Raise an exception if there is a problem; it is up to you to check
    # that the connection has sufficient authorisation using @connection.binddn

    def add(dn, av)
      raise LDAP::ResultError::UnwillingToPerform, "add not implemented"
    end

    # Handle a del request; override this

    def del(dn)
      raise LDAP::ResultError::UnwillingToPerform, "delete not implemented"
    end

    # Handle a modifydn request; override this

    def modifydn(entry, newrdn, deleteoldrdn, newSuperior)
      raise LDAP::ResultError::UnwillingToPerform, "modifydn not implemented"
    end

    # Handle a compare request; override this. Return true or false,
    # or raise an exception for errors.

    def compare(entry, attr, val)
      raise LDAP::ResultError::UnwillingToPerform, "compare not implemented"
    end

  end # class Operation
end # class Server
end # module LDAP
