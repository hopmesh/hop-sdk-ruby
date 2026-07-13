# frozen_string_literal: true

# A standalone, self-hostable Hop endpoint (the two-process deployment shape). Run this, then run
# client.rb with the address it prints. In production HNS would resolve a name to this host/port/key,
# and you would persist the key so the address is stable across restarts.
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "json"
require "hop"

$stdout.sync = true # a long-running server: flush logs immediately instead of buffering
port = (ENV["PORT"] || "9944").to_i

server = Hop::Endpoint.new
server.on("acme/orders") do |req, reply|
  # req.from is the cryptographically VERIFIED sender, not a spoofable header. No auth middleware.
  puts "[server] #{req.service}/#{req.method} from #{req.from[0, 12]}: #{req.text}"
  reply.call(201, JSON.generate({ ok: true, received: JSON.parse(req.args) }))
end

Hop::TcpBearer.listen(server, port)
puts "hop endpoint listening on tcp://0.0.0.0:#{port}"
puts "address: #{server.address}"
puts "\ntry it:\n  ruby examples/client.rb #{server.address} localhost #{port}"

sleep # keep the endpoint (and its pump thread) alive
