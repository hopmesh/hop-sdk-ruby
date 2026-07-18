# frozen_string_literal: true

# Derisking proof: the hops:// service round trip through the raw C ABI from Ruby (via Fiddle),
# mirroring core/hop/src/cabi.rs. Two nodes, a byte-pipe bearer, a request in, 200 + body back out.
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "hop/ffi"

F = Hop::FFI
F.assert_abi!
puts "ABI ok: #{F::ABI_VERSION.call}"

LA = 11
LB = 22

def pump(a, b)
  1000.times do
    moved = false
    F.drain_outgoing(a).each { |_l, buf| moved = true; F.received(b, LB, buf) }
    F.drain_outgoing(b).each { |_l, buf| moved = true; F.received(a, LA, buf) }
    break unless moved
  end
end

a = F.node_new
b = F.node_new

F.tick(a, 1000)
F.tick(b, 1000)
F.connected(a, LA, true)
F.connected(b, LB, false)
pump(a, b)
F.publish_prekey(a)
F.publish_prekey(b)
pump(a, b)

b_addr = F.address(b)
req_id = F.send_service_request(a, b_addr, "weather", "report", "temp=21")
puts "request fired, reqId: #{req_id.unpack1("H*")[0, 12]}"
pump(a, b)

frm, rid, service, method, args = F.take_service_requests(b).first
puts "B received: #{service}/#{method} = #{args} from #{F.to_b58(frm)[0, 12]}"

F.send_service_response(b, frm, rid, 200, "stored")
pump(a, b)

_rf, for_id, status, body = F.take_service_responses(a).first
F.accept_service_response(a, for_id)
puts "A got response: #{status} #{body}  ties to reqId: #{for_id == req_id}"

passed = service == "weather" && status == 200 && body == "stored" && for_id == req_id
F.node_free(a)
F.node_free(b)
puts(passed ? "\nPASS: full hops:// round trip through the C ABI from Ruby." : "\nFAIL")
exit(passed ? 0 : 1)
