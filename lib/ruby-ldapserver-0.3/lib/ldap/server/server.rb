require 'ldap/server/connection'
require 'ldap/server/operation'
require 'openssl'

module LDAP
class Server

  attr_accessor :root_dse

  DEFAULT_OPT = {
      :port=>389,
      :nodelay=>true,
  }

  # Create a new server. Options include all those to tcpserver/preforkserver
  # plus:
  #   :operation_class=>Class			- set Operation handler class
  #   :operation_args=>[...]			- args to Operation.new
  #   :ssl_key_file=>pem, :ssl_cert_file=>pem	- enable SSL
  #   :ssl_ca_path=>directory			- verify peer certificates
  #   :schema=>Schema				- Schema object
  #   :namingContexts=>[dn, ...]		- base DN(s) we answer

  def initialize(opt = DEFAULT_OPT)
    @opt = opt
    @opt[:server] = self
    @opt[:operation_class] ||= LDAP::Server::Operation
    @opt[:operation_args] ||= []
    LDAP::Server.ssl_prepare(@opt)
    @schema = opt[:schema]	# may be nil
    @root_dse = Hash.new { |h,k| h[k] = [] }.merge({
	'objectClass' => ['top','openLDAProotDSE','extensibleObject'],
	'supportedLDAPVersion' => ['3'],
	#'altServer' =>
	#'supportedExtension' =>
	#'supportedControl' =>
	#'supportedSASLMechanisms' =>
    })
    @root_dse['subschemaSubentry'] = [@schema.subschema_dn] if @schema
    @root_dse['namingContexts'] = opt[:namingContexts] if opt[:namingContexts]
  end

  # create opt[:ssl_ctx] from the other ssl options

  def self.ssl_prepare(opt) # :nodoc:
    if opt[:ssl_key_file] and opt[:ssl_cert_file]
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.key = OpenSSL::PKey::RSA.new(File::read(opt[:ssl_key_file]))
      ctx.cert = OpenSSL::X509::Certificate.new(File::read(opt[:ssl_cert_file]))
      if opt[:ssl_ca_path]
        ctx.ca_path = opt[:ssl_ca_path]
        ctx.verify_mode = 
          OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
      else
        $stderr.puts "Warning: SSL peer certificate won't be verified"
      end
      opt[:ssl_ctx] = ctx
    end
  end

  def run_tcpserver
    require 'ldap/server/tcpserver'

    opt = @opt
    @thread = LDAP::Server.tcpserver(@opt) do
      LDAP::Server::Connection::new(self,opt).handle_requests
    end
  end

  def run_prefork
    require 'ldap/server/preforkserver'

    opt = @opt
    @thread = LDAP::Server.preforkserver(@opt) do
      LDAP::Server::Connection::new(self,opt).handle_requests
    end
  end

  def join
    @thread.join
  end

  def stop
    @thread.raise Interrupt
    @thread.join
  end

end # class Server
end # module LDAP
