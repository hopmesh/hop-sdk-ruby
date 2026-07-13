# frozen_string_literal: true

# The Sinatra/Rails-shaped DX, running on real hop-core over the C ABI. A server endpoint registers a
# receiver; a client calls it and gets a reply. Delivery is delay-tolerant underneath.
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "json"
require "hop"

server = Hop::Endpoint.new
client = Hop::Endpoint.new

# --- this is the whole server: mount a receiver, reply with a status + body ---
server.on("acme/orders") do |req, reply|
  puts "  [server] #{req.service}/#{req.method} from #{req.from[0, 10]} body=#{req.text}"
  order = JSON.parse(req.args)
  reply.call(200, JSON.generate({ ok: true, id: 42, item: order["item"] })) # uint16 status, JSON body
end

# wire the two endpoints together (in-process bearer; swap for TCP to make it reachable by any device)
Hop.connect_in_process(server, client)

puts "server address: #{server.address}"
puts "client address: #{client.address}"

# --- client calls the service, like an HTTP request, but forward-secret + delay-tolerant ---
status, body = client.request(server.address, "acme/orders", "create", JSON.generate({ item: "widget" }))
puts "  [client] <- #{status} #{body}"

parsed = JSON.parse(body)
passed = status == 200 && parsed["ok"] == true && parsed["item"] == "widget"
server.close
client.close
puts(passed ? "\nPASS: hop.on(service) + reply.call(status, body) over real hop-core." : "\nFAIL")
exit(passed ? 0 : 1)
