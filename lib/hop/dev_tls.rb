# frozen_string_literal: true

require "openssl"

module Hop
  # DEV/TEST ONLY: an in-process self-signed cert for the discovery example + test (no `openssl` CLI,
  # no gems; OpenSSL ships with Ruby). Never use a self-signed cert in production; there a real WebPKI
  # cert proves the domain.
  module DevTls
    # An SSLContext backed by a fresh in-process self-signed cert (RSA-2048, CN=<cn>, 1h).
    def self.server_context(cn = "localhost")
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      cert.sign(key, OpenSSL::Digest.new("SHA256"))
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.cert = cert
      ctx.key = key
      ctx
    end
  end
end
