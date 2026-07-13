# frozen_string_literal: true

# Proves the full DNS-free discovery chain: a client resolves a domain by name, the TLS cert proves the
# domain (WebPKI), the served reach record self-certifies the address, and the WSS handshake confirms
# it, then a hops:// round trip runs over the WebSocket. One process, a real self-signed HTTPS server
# (production uses a real cert; here we accept the in-process self-signed one with insecure_tls).
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "hop"
require "hop/dev_tls"

PORT = 8443
PUBLIC = "wss://localhost:#{PORT}/_hop"

# self-signed cert for localhost, generated IN-PROCESS (no openssl CLI); production has a real WebPKI cert
tls = Hop::DevTls.server_context

# --- the server: an HTTPS server (wss /_hop + GET /.well-known/hop), wired in ONE call ---
server = Hop::Endpoint.new
server.on("acme/orders") do |req, reply|
  puts "  [server] #{req.service}/#{req.method} from #{req.from[0, 10]}: #{req.text}"
  reply.call(201, req.args)
end
server.attach(PORT, tls, PUBLIC)
puts "endpoint on https://localhost:#{PORT} (well-known + wss)  addr=#{server.address[0, 12]}"

# --- the client: resolve by NAME, verifying the record, then round-trip over WSS ---
client = Hop::Endpoint.new
address = client.dial_by_name("https://localhost:#{PORT}", insecure_tls: true)
puts "  [client] resolved the domain -> #{address[0, 12]} (reach record verified)"

status, body = client.request(address, "acme/orders", "create", "widget")
puts "  [client] <- #{status} #{body}"

passed = status == 201 && body == "widget"
server.close
client.close
puts(passed ? "\nPASS: name -> verified address -> WSS hops:// round trip." : "\nFAIL")
exit(passed ? 0 : 1)
