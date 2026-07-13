# frozen_string_literal: true

# Discovery: bind a name to a Hop address without DNSSEC, using the domain's TLS cert (WebPKI) plus a
# self-certifying reachability record served at /.well-known/hop. See docs/endpoint-sdk.md.
require "json"
require "base64"
require "net/http"
require "uri"
require "openssl"
require "hop/ffi"

module Hop
  module Discovery
    WELL_KNOWN_PATH = "/.well-known/hop"

    def self.well_known_body(endpoint, public_url, ttl_secs = 3600)
      record = endpoint.sign_reach(public_url, ttl_secs)
      JSON.generate({ "address" => endpoint.address, "endpoint" => public_url, "reach" => Base64.strict_encode64(record) })
    end

    # Fetch + verify base_url's well-known. Returns {address:, address_bytes:, wss_url:}. Raises on a
    # missing/malformed/unverified record.
    def self.resolve(base_url, insecure_tls: false)
      uri = URI.parse(base_url)
      http = Net::HTTP.new(uri.host, uri.port || 443)
      http.use_ssl = true
      http.verify_mode = insecure_tls ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
      res = http.get(WELL_KNOWN_PATH)
      raise "well-known fetch failed: HTTP #{res.code}" unless res.code.to_i == 200

      body = JSON.parse(res.body)
      info = Hop::FFI.verify_reach(Base64.strict_decode64(body["reach"]), Time.now.to_i)
      raise "reach record failed verification (bad signature or expired)" unless info

      { address: Hop::FFI.to_b58(info[:address]), address_bytes: info[:address], wss_url: info[:endpoint] }
    end
  end
end
