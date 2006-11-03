module LDAP

# compatible with ruby-ldap
class Error < StandardError
end

class ResultError < Error
end

# This exception is raised when we need to kill an existing Operation
# thread because of a received abandonRequest or bindRequest
class Abandon < Interrupt
end

# ResultError constants from RFC 2251 4.1.10; these are all exceptions
# which can be raised

class ResultError
  class Success < self;				def to_i; 0; end; end
  class OperationsError < self;			def to_i; 1; end; end
  class ProtocolError < self;			def to_i; 2; end; end
  class TimeLimitExceeded < self; 		def to_i; 3; end; end
  class SizeLimitExceeded < self;		def to_i; 4; end; end
  class CompareFalse < self;			def to_i; 5; end; end
  class CompareTrue < self;			def to_i; 6; end; end
  class AuthMethodNotSupported < self;		def to_i; 7; end; end
  class StrongAuthRequired < self;		def to_i; 8; end; end
  class Referral < self;			def to_i; 10; end; end
  class AdminLimitExceeded < self;		def to_i; 11; end; end
  class UnavailableCriticalExtension < self;	def to_i; 12; end; end
  class ConfidentialityRequired < self;		def to_i; 13; end; end
  class SaslBindInProgress < self;		def to_i; 14; end; end
  class NoSuchAttribute < self;			def to_i; 16; end; end
  class UndefinedAttributeType < self;		def to_i; 17; end; end
  class InappropriateMatching < self;		def to_i; 18; end; end
  class ConstraintViolation < self;		def to_i; 19; end; end
  class AttributeOrValueExists < self;		def to_i; 20; end; end
  class InvalidAttributeSyntax < self;		def to_i; 21; end; end
  class NoSuchObject < self;			def to_i; 32; end; end
  class AliasProblem < self;			def to_i; 33; end; end
  class InvalidDNSyntax < self;			def to_i; 34; end; end
  class IsLeaf < self;				def to_i; 35; end; end
  class AliasDereferencingProblem < self;	def to_i; 36; end; end
  class InappropriateAuthentication < self;	def to_i; 48; end; end
  class InvalidCredentials < self;		def to_i; 49; end; end
  class InsufficientAccessRights < self;	def to_i; 50; end; end
  class Busy < self;				def to_i; 51; end; end
  class Unavailable < self;			def to_i; 52; end; end
  class UnwillingToPerform < self;		def to_i; 53; end; end
  class LoopDetect < self;			def to_i; 54; end; end
  class NamingViolation < self;			def to_i; 64; end; end
  class ObjectClassViolation < self;		def to_i; 65; end; end
  class NotAllowedOnNonLeaf < self;		def to_i; 66; end; end
  class NotAllowedOnRDN < self;			def to_i; 67; end; end
  class EntryAlreadyExists < self;		def to_i; 68; end; end
  class ObjectClassModsProhibited < self;	def to_i; 69; end; end
  class AffectsMultipleDSAs < self;		def to_i; 71; end; end
  class Other < self;				def to_i; 80; end; end

  # Reverse lookup: so you can do raise LDAP::ResultError[53]

  N_TO_CLASS = {
    53 => UnwillingToPerform,
    # FIXME: please fill in the rest
  }
  def self.[] (n)
    return N_TO_CLASS[n] || self
  end
end # class ResultError

end # module LDAP
