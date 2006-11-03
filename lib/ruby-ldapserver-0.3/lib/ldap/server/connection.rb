require 'thread'
require 'openssl'
require 'ldap/server/result'

module LDAP
class Server

  # An object which handles an LDAP connection. Note that LDAP allows
  # requests and responses to be exchanged asynchronously: e.g. a client
  # can send three requests, and the three responses can come back in
  # any order. For that reason, we start a new thread for each request,
  # and we need a mutex on the io object so that multiple responses don't
  # interfere with each other.

  class Connection
    attr_reader :binddn, :version, :opt

    def initialize(io, opt={})
      @io = io
      @opt = opt
      @mutex = Mutex.new
      @active_reqs = {}   # map message ID to thread object
      @binddn = nil
      @version = 3
      @logger = @opt[:logger] || $stderr
      @ssl = false

      startssl if @opt[:ssl_on_connect]
    end

    def log(msg)
      @logger << "[#{@io.peeraddr[3]}]: #{msg}\n"
    end

    def startssl # :yields:
      @mutex.synchronize do
        raise LDAP::ResultError::OperationsError if @ssl or @active_reqs.size > 0
        yield if block_given?
        @io = OpenSSL::SSL::SSLSocket.new(@io, @opt[:ssl_ctx])
        @io.sync_close = true
        @io.accept
        @ssl = true
      end
    end

    # Read one ASN1 element from the given stream.
    # Return String containing the raw element.

    def ber_read(io)
      blk = io.read(2)		# minimum: short tag, short length
      throw(:close) if blk.nil?
      tag = blk[0] & 0x1f
      len = blk[1]

      if tag == 0x1f		# long form
        tag = 0
        while true
          ch = io.getc
          blk << ch
          tag = (tag << 7) | (ch & 0x7f)
          break if (ch & 0x80) == 0
        end
        len = io.getc
        blk << len
      end

      if (len & 0x80) != 0	# long form
        len = len & 0x7f
        raise LDAP::ResultError::ProtocolError, "Indefinite length encoding not supported" if len == 0
        offset = blk.length
        blk << io.read(len)
        # is there a more efficient way of doing this?
        len = 0
        blk[offset..-1].each_byte { |b| len = (len << 8) | b }
      end

      offset = blk.length
      blk << io.read(len)
      return blk
      # or if we wanted to keep the partial decoding we've done:
      # return blk, [blk[0] >> 6, tag], offset
    end

    def handle_requests
      operationClass = @opt[:operation_class]
      ocArgs = @opt[:operation_args] || []
      catch(:close) do
        while true
          begin
            blk = ber_read(@io)
            asn1 = OpenSSL::ASN1::decode(blk)
            # Debugging:
            # puts "Request: #{blk.unpack("H*")}\n#{asn1.inspect}" if $debug

            raise LDAP::ResultError::ProtocolError, "LDAPMessage must be SEQUENCE" unless asn1.is_a?(OpenSSL::ASN1::Sequence)
            raise LDAP::ResultError::ProtocolError, "Bad Message ID" unless asn1.value[0].is_a?(OpenSSL::ASN1::Integer)
            messageId = asn1.value[0].value

            protocolOp = asn1.value[1]
            raise LDAP::ResultError::ProtocolError, "Bad protocolOp" unless protocolOp.is_a?(OpenSSL::ASN1::ASN1Data)
            raise LDAP::ResultError::ProtocolError, "Bad protocolOp tag class" unless protocolOp.tag_class == :APPLICATION

            # controls are not properly implemented
            c = asn1.value[2]
            if c.is_a?(OpenSSL::ASN1::ASN1Data) and c.tag_class == :APPLICATION and c.tag == 0
              controls = c.value
            end

            case protocolOp.tag
            when 0 # BindRequest
              abandon_all
              @binddn, @version = operationClass.new(self,messageId,*ocArgs).
                                  do_bind(protocolOp, controls)

            when 2 # UnbindRequest
              throw(:close)

            when 3 # SearchRequest
              # Note: RFC 2251 4.4.4.1 says behaviour is undefined if
              # client sends an overlapping request with same message ID,
              # so we don't have to worry about the case where there is
              # already a thread with this id in @active_reqs.
              # However, to avoid a race we copy messageId/
              # protocolOp/controls into thread-local variables, because
              # they will change when the next request comes in.
              #
              # There is a theoretical race condition here: a client could
              # send an abandon request before Thread.current is assigned to
              # @active_reqs[thrm]. It's not a problem, because abandon isn't
              # guaranteed to work anyway. Doing it this way ensures that
              # @active_reqs does not leak memory on a long-lived connection.

              Thread.new(messageId,protocolOp,controls) do |thrm,thrp,thrc|
                begin
                  @active_reqs[thrm] = Thread.current
                  operationClass.new(self,thrm,*ocArgs).do_search(thrp, thrc)
                ensure
                  @active_reqs.delete(thrm)
                end
              end

            when 6 # ModifyRequest
              Thread.new(messageId,protocolOp,controls) do |thrm,thrp,thrc|
                begin
                  @active_reqs[thrm] = Thread.current
                  operationClass.new(self,thrm,*ocArgs).do_modify(thrp, thrc)
                ensure
                  @active_reqs.delete(thrm)
                end
              end

            when 8 # AddRequest
              Thread.new(messageId,protocolOp,controls) do |thrm,thrp,thrc|
                begin
                  @active_reqs[thrm] = Thread.current
                  operationClass.new(self,thrm,*ocArgs).do_add(thrp, thrc)
                ensure
                  @active_reqs.delete(thrm)
                end
              end

            when 10 # DelRequest
              Thread.new(messageId,protocolOp,controls) do |thrm,thrp,thrc|
                begin
                  @active_reqs[thrm] = Thread.current
                  operationClass.new(self,thrm,*ocArgs).do_del(thrp, thrc)
                ensure
                  @active_reqs.delete(thrm)
                end
              end

            when 12 # ModifyDNRequest
              Thread.new(messageId,protocolOp,controls) do |thrm,thrp,thrc|
                begin
                  @active_reqs[thrm] = Thread.current
                  operationClass.new(self,thrm,*ocArgs).do_modifydn(thrp, thrc)
                ensure
                  @active_reqs.delete(thrm)
                end
              end

            when 14 # CompareRequest
              Thread.new(messageId,protocolOp,controls) do |thrm,thrp,thrc|
                begin
                  @active_reqs[thrm] = Thread.current
                  operationClass.new(self,thrm,*ocArgs).do_compare(thrp, thrc)
                ensure
                  @active_reqs.delete(thrm)
                end
              end

            when 16 # AbandonRequest
              abandon(protocolOp.value)

            else
              raise LDAP::ResultError::ProtocolError, "Unrecognised protocolOp tag #{protocolOp.tag}"
            end

          rescue LDAP::ResultError::ProtocolError, OpenSSL::ASN1::ASN1Error => e
            send_notice_of_disconnection(LDAP::ResultError::ProtocolError.new.to_i, e.message)
            throw(:close)

          # all other exceptions propagate up and are caught by tcpserver
          end
        end
      end
      abandon_all
    end

    def write(data)
      @mutex.synchronize do
        @io.write(data)
        @io.flush
      end
    end

    def writelock
      @mutex.synchronize do
        yield @io
        @io.flush
      end
    end

    def abandon(messageID)
      @mutex.synchronize do
        thread = @active_reqs.delete(messageID)
        thread.raise LDAP::Abandon if thread and thread.alive?
      end
    end

    def abandon_all
      return if @active_reqs.size == 0
      @mutex.synchronize do
        @active_reqs.each do |id, thread|
          thread.raise LDAP::Abandon if thread.alive?
        end
        @active_reqs = {}
      end
    end

    def send_unsolicited_notification(resultCode, opt={})
      protocolOp = [
        OpenSSL::ASN1::Enumerated(resultCode),
        OpenSSL::ASN1::OctetString(opt[:matchedDN] || ""),
        OpenSSL::ASN1::OctetString(opt[:errorMessage] || ""),
      ]
      if opt[:referral]
        rs = opt[:referral].collect { |r| OpenSSL::ASN1::OctetString(r) }
        protocolOp << OpenSSL::ASN1::Sequence(rs, 3, :IMPLICIT, :APPLICATION)
      end
      if opt[:responseName]
        protocolOp << OpenSSL::ASN1::OctetString(opt[:responseName], 10, :IMPLICIT, :APPLICATION)
      end
      if opt[:response]
        protocolOp << OpenSSL::ASN1::OctetString(opt[:response], 11, :IMPLICIT, :APPLICATION)
      end
      message = [
        OpenSSL::ASN1::Integer(0),
        OpenSSL::ASN1::Sequence(protocolOp, 24, :IMPLICIT, :APPLICATION),
      ]
      message << opt[:controls] if opt[:controls]
      write(OpenSSL::ASN1::Sequence(message).to_der)
    end

    def send_notice_of_disconnection(resultCode, errorMessage="")
      send_unsolicited_notification(resultCode,
        :errorMessage=>errorMessage,
        :responseName=>"1.3.6.1.4.1.1466.20036"
      )
    end
  end
end # class Server
end # module LDAP
