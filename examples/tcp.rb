# frozen_string_literal: true

# Proves the Internet bearer: a server endpoint LISTENS on a TCP port, a client endpoint DIALS it over
# a real socket, and the hops:// round trip completes over TCP with real Noise. One process, real
# loopback sockets (see server.rb + client.rb for the two-process deployment shape).
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "json"
require "hop"

PORT = 9944

server = Hop::Endpoint.new
server.on("acme/orders") do |req, reply|
  puts "  [server] #{req.service}/#{req.method} from #{req.from[0, 10]} over TCP: #{req.text}"
  reply.call(201, JSON.generate({ ok: true, item: JSON.parse(req.args)["item"] }))
end
Hop::TcpBearer.listen(server, PORT)
puts "server listening on tcp://localhost:#{PORT}  addr=#{server.address[0, 12]}"

client = Hop::Endpoint.new
Hop::TcpBearer.dial(client, "localhost", PORT) # in production: HNS resolves name -> host/port/key

# send the request by the server's ADDRESS (a client would resolve this from HNS, not share a process)
status, body = client.request(server.address, "acme/orders", "create", JSON.generate({ item: "widget" }))
puts "  [client] <- #{status} #{body}"

parsed = JSON.parse(body)
passed = status == 201 && parsed["ok"] == true && parsed["item"] == "widget"
server.close
client.close
puts(passed ? "\nPASS: hops:// round trip over a real TCP Internet bearer." : "\nFAIL")
exit(passed ? 0 : 1)
