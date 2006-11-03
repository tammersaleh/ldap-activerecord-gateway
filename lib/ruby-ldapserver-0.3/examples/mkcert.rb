require 'openssl'

# Taken directly from echo_svr.rb in the Ruby openssl examples

key = OpenSSL::PKey::RSA.new(1024){ print "."; $stdout.flush }
puts
cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = 0
name = OpenSSL::X509::Name.new([["C","JP"],["O","TEST"],["CN","localhost"]])
cert.subject = name
cert.issuer = name
cert.not_before = Time.now
cert.not_after = Time.now + 3600
cert.public_key = key.public_key
ef = OpenSSL::X509::ExtensionFactory.new(nil,cert)
cert.extensions = [
  ef.create_extension("basicConstraints","CA:FALSE"),
  ef.create_extension("subjectKeyIdentifier","hash"),
  ef.create_extension("extendedKeyUsage","serverAuth"),
  ef.create_extension("keyUsage",
                      "keyEncipherment,dataEncipherment,digitalSignature")
]
ef.issuer_certificate = cert
cert.add_extension ef.create_extension("authorityKeyIdentifier",
                                       "keyid:always,issuer:always")
cert.sign(key, OpenSSL::Digest::SHA1.new)

# Write to disk
File.open("key.pem","w",0600) { |f| f << key.to_pem }
File.open("cert.pem","w",0644) { |f| f << cert.to_pem }
