<p align="center">
  <img alt="Hop" src="https://hopme.sh/hop-mark.svg" width="200">
</p>

<h1 align="center">hop-endpoint</h1>

<p align="center">
  <b>Receive Hop messages in your Ruby service.</b><br>
  A Sinatra/Rails-shaped endpoint on the <a href="https://hopme.sh">Hop</a> mesh, over the <code>libhop</code> C ABI.
</p>

<p align="center">
  <a href="https://rubygems.org/gems/hop-endpoint"><img src="https://img.shields.io/gem/v/hop-endpoint?color=cc342d&label=gem" alt="gem"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-3ddc84" alt="license">
  <img src="https://img.shields.io/badge/ruby-%E2%89%A53.0-6ea8fe" alt="ruby >=3.0">
</p>

---

Hop is a **delay-tolerant mesh**: end-to-end encrypted datagrams that hop device to device, over BLE,
Wi-Fi, and the internet, until they reach the person or service you meant. Held, never dropped.

`hop-endpoint` is the **server side**: your Ruby service becomes a first-class address on the mesh, so
senders hand messages straight to it. Self-host is an import, not an ops project. No inbound port to open
to the world, no bearer tokens to rotate, no message queue to run: the sender identity is authenticated
by the ratchet, and delivery is durable and store-and-forward. **Zero gems**, `Fiddle` is Ruby's stdlib FFI.

## Install

```sh
gem install hop-endpoint
```

You also need `libhop`, the Rust protocol core, as a prebuilt binary or a local build, pointed to with
`HOP_LIBDIR`. See [libhop](https://github.com/hopmesh/libhop). Ruby 3.0+ (`Fiddle`, `OpenSSL`, `Socket`,
`Net::HTTP`, `JSON` are all stdlib).

## Quick start

```ruby
require "hop"
require "json"

hop = Hop::Endpoint.new

hop.on("acme/orders") do |req, reply|
  # req.from is a VERIFIED identity (base58), not a spoofable header
  order = JSON.parse(req.text)
  reply.call(201, JSON.generate({ ok: true, order: order })) # uint16 status + body
end

Hop::TcpBearer.listen(hop, 9944) # reachable by any device
puts hop.address                 # publish this (or its name); senders reach you by it
```

**The DX looks like HTTP; the semantics are better.** Inbound is a durable, store-and-forward consume; a
reply is a new addressed message that may arrive later, even after a restart. It works when the peer is
offline, and there is no auth layer to bolt on, the identity is cryptographic. core is poll-model, so the
endpoint runs a background pump thread (the node is thread-safe).

## Reachable by name

Make an endpoint reachable at `myaddress.com` with no new port, on a pure-stdlib WebSocket bearer (zero
gems). `attach` wires the WSS bearer (`/_hop`) and the discovery route (`/.well-known/hop`) in one call:

```ruby
require "openssl"
ctx = OpenSSL::SSL::SSLContext.new
ctx.cert = OpenSSL::X509::Certificate.new(File.read("cert.pem"))
ctx.key  = OpenSSL::PKey::RSA.new(File.read("key.pem"))
hop.attach(443, ctx, "wss://myaddress.com/_hop")
```

A client reaches it by name, verified end to end:

```ruby
address = client.dial_by_name("https://myaddress.com")
status, body = client.request(address, "acme/orders", "create", order)
```

TLS proves the domain, a signed **reach record** proves the address, and the Noise handshake confirms it.
Spoof the `A` record or MITM the lookup and the attacker still can't forge the cert or complete the
handshake as the address, and a request sealed to that address is unreadable to anyone else.

## Rails / Rack

The endpoint is just an object with a pump thread, so it drops into a long-running process. In a Rails
app, build one `Hop::Endpoint` in an initializer, keep it in a constant or a singleton, register your
`on(...)` handlers there, and call `attach` to serve WSS on the same host. The handler block runs off the
request cycle (it is the mesh inbox, not a controller action): enqueue a job, write a row, then
`reply.call`.

## How it maps to the core

The endpoint is a `hop-core` node in host-a-mailbox mode, over the same C ABI every Hop SDK binds (via
`Fiddle`), with zero core changes:

| Endpoint                   | libhop C ABI                                               |
| -------------------------- | ---------------------------------------------------------- |
| `hop.on(svc) { }`          | `hop_subscribe` + `hop_poll_service_requests`              |
| `reply.call(status, body)` | `hop_send_service_response` (status is a `uint16`)         |
| `hop.request(...)`         | `hop_send_service_request` + `hop_poll_service_responses`  |
| the Internet bearer        | `hop_link_up` / `hop_bytes_received` / `hop_drain_outgoing`|

## Examples

Point `HOP_LIBDIR` at a built `libhop`, then:

```sh
ruby -Ilib test/test_hop.rb    # in-process + reach record + WSS discovery, all pass
ruby examples/raw_roundtrip.rb # raw C ABI round trip (proves the Fiddle bindings)
ruby examples/echo.rb          # the hop.on / reply DX in-process
ruby examples/tcp.rb           # the same round trip over a real TCP bearer
ruby examples/discovery.rb     # the full reachable-by-name chain (HTTPS + WSS)
```

Two-process shape (a standalone server plus a client that dials it):

```sh
ruby examples/server.rb                    # prints its address, listens on tcp://0.0.0.0:9944
ruby examples/client.rb <address> localhost 9944
```

## Status

Prototype. Built and working: the `on` block handler and `reply`, the client `request`, the in-process /
TCP / WSS bearers, base58 addressing, reach-record `attach` / `dial_by_name` discovery, sibling-replica
clustering, the ABI-version assert, and a use-after-free-safe `close` (bearer threads that fire after
teardown short-circuit instead of touching a freed node). HNS name publish/resolve and multi-tenant
hosting are on the roadmap (each an SDK-level follow-up, not a core change).

## The Hop family

`hop-endpoint` is one of several SDKs over the same C ABI. Same surface, your language:
[node](https://github.com/hopmesh/hop-sdk-node) ·
[python](https://github.com/hopmesh/hop-sdk-python) ·
[go](https://github.com/hopmesh/hop-sdk-go) ·
[ruby](https://github.com/hopmesh/hop-sdk-ruby) ·
[crystal](https://github.com/hopmesh/hop-sdk-crystal) ·
[elixir](https://github.com/hopmesh/hop-sdk-elixir).
The protocol core is [libhop](https://github.com/hopmesh/libhop) / [hop-core](https://github.com/hopmesh/hop-core).

## License

[Apache-2.0](./LICENSE.md), embed it freely. Only the protocol core (`hop-core`) is FSL-1.1-ALv2,
source-available and converting to Apache-2.0 after two years.
