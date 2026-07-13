# frozen_string_literal: true

# Calls a self-hosted Hop endpoint over TCP. The address would normally come from an HNS lookup; here
# you paste the one server.rb printed.
#   ruby examples/client.rb <server-address> [host] [port]
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "json"
require "hop"

address = ARGV[0]
unless address
  warn "usage: ruby examples/client.rb <server-address> [host] [port]"
  exit(2)
end
host = ARGV[1] || "localhost"
port = (ARGV[2] || "9944").to_i

client = Hop::Endpoint.new
Hop::TcpBearer.dial(client, host, port)

begin
  status, body = client.request(address, "acme/orders", "create", JSON.generate({ item: "widget", qty: 3 }))
  puts "<- #{status} #{body}"
rescue StandardError => e
  warn "request failed: #{e.message}"
  exit(1)
ensure
  client.close
end
