# hop-endpoint (Ruby endpoint SDK, prototype)

Receive Hop messages in Ruby with a Sinatra/Rails-shaped surface, over the `libhop` C ABI. Same idea as
`sdk/node`, `sdk/python`, and `sdk/elixir`: your service becomes directly reachable on the mesh, so
senders hand messages straight to it without a relay. **Zero gems**, `Fiddle` is Ruby's stdlib FFI.

```ruby
require "hop"

hop = Hop::Endpoint.new

hop.on("acme/orders") do |req, reply|
  # req.from is a cryptographically VERIFIED identity (base58), not a spoofable header
  order = JSON.parse(req.args)
  reply.call(201, JSON.generate({ ok: true, order: order })) # uint16 status + bytes body
end

Hop::TcpBearer.listen(hop, 9944) # reachable by any device; in production HNS resolves name -> host/port/key
puts hop.address                 # publish this (or its HNS name)
```

## What it is (and isn't)

The endpoint is a `hop-core` node in service-host mode. The mapping onto the C ABI is exact:

| Endpoint concept        | libhop C ABI                                               |
| ----------------------- | ---------------------------------------------------------- |
| `hop.on(service) {...}`  | `hop_subscribe` + `hop_poll_service_requests`             |
| `reply.call(status, body)` | `hop_send_service_response` (status is a `uint16`)      |
| `hop.request(...)`      | `hop_send_service_request` + `hop_poll_service_responses`  |
| the Internet bearer     | `hop_link_up` / `hop_bytes_received` / `hop_drain_outgoing` |

**The DX is HTTP-shaped; the semantics are not.** Inbound is a durable store-and-forward consume; a
reply is a new addressed message that may arrive later, even after a restart. It is a queue consumer,
not a synchronous route, that is what makes it offline-tolerant. core is poll-model, so the endpoint
runs a background pump thread (the node is thread-safe).

## Run the proofs

Build `libhop` first (or set `HOP_LIBDIR`):

```sh
cargo build -p hop                          # from the repo root -> target/debug/libhop.<dylib|so>
cd sdk/ruby
ruby examples/raw_roundtrip.rb              # raw C ABI round trip (proves the Fiddle bindings)
ruby examples/echo.rb                       # the hop.on / reply DX in-process
ruby examples/tcp.rb                        # the same round trip over a real TCP bearer
ruby examples/discovery.rb                  # WSS + WebPKI + reach-record discovery (in-process cert)
ruby -Ilib test/test_hop.rb                 # in-process, reach record, + WSS discovery, all pass
```

Two-process shape (a standalone server + a client that dials it):

```sh
ruby examples/server.rb                      # prints its address, listens on tcp://0.0.0.0:9944
ruby examples/client.rb <address> localhost 9944
```

## Reachable by name (WSS + discovery)

Make an endpoint reachable at `myaddress.com` with **no new port and no DNSSEC**, using a **pure-stdlib**
WebSocket bearer (zero gems):

```ruby
require "openssl"
ctx = OpenSSL::SSL::SSLContext.new
ctx.cert = OpenSSL::X509::Certificate.new(File.read("cert.pem"))
ctx.key  = OpenSSL::PKey::RSA.new(File.read("key.pem"))
hop.attach(443, ctx, "wss://myaddress.com/_hop") # WSS /_hop + /.well-known/hop in one call
```

```ruby
address = client.dial_by_name("https://myaddress.com")        # WebPKI + self-certifying
status, body = client.request(address, "acme/orders", "create", order)
```

Trust, no DNSSEC: `dial_by_name` fetches `/.well-known/hop` (TLS proves the domain), verifies the
self-certifying reach record (signed by the address), dials the WSS, and the Noise handshake confirms
the address. `test/test_hop.rb` proves the full chain against a self-signed HTTPS server.

## Rails / Rack

The endpoint is just an object with a pump thread, so it drops into a long-running process. In a Rails
app, build one `Hop::Endpoint` in an initializer, keep it in a constant or a singleton, register your
`on(...)` handlers there, and call `attach` if you want the app reachable over WSS on the same host. The
handler block runs off the request cycle (it is the mesh inbox, not a controller action), so treat it
like a background consumer: enqueue a job, write a row, then `reply.call`.

## Prototype scope

Built and working: `hop.on` (block handler), `reply`, `request`, the pump thread, TCP + WSS bearers,
base58 addressing, reach records + `attach`/`dial_by_name` discovery, ABI-version assertion, and a
clean, use-after-free-safe `close` (bearer threads that fire after teardown short-circuit instead of
touching a freed node). Follow-ups (each additive, none a core change): the no-domain gossip case,
delegated keys, multi-tenant hosting. Not yet a required CI job.
Design: `docs/endpoint-sdk.md`.
