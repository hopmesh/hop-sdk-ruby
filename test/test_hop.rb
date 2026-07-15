# frozen_string_literal: true

require "minitest/autorun"
require "hop"
require "hop/discovery"
require "hop/dev_tls"

class TestHop < Minitest::Test
  def test_reach_record_sign_verify_and_tamper
    e = Hop::Endpoint.new
    rec = e.sign_reach("wss://myaddress.com/_hop", 3600)
    info = Hop::FFI.verify_reach(rec, Time.now.to_i)
    refute_nil info
    assert_equal "wss://myaddress.com/_hop", info[:endpoint]
    assert_equal e.address, Hop::FFI.to_b58(info[:address])

    bad = rec.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 0xFF)
    assert_nil Hop::FFI.verify_reach(bad, Time.now.to_i)
  ensure
    e.close
  end

  def test_in_process_round_trip
    server = Hop::Endpoint.new
    server.on("acme/orders") { |req, reply| reply.call(200, "got:#{req.args}") }
    client = Hop::Endpoint.new
    Hop.connect_in_process(server, client)
    status, body = client.request(server.address_bytes, "acme/orders", "create", "temp=21")
    assert_equal 200, status
    assert_equal "got:temp=21", body
  ensure
    server&.close
    client&.close
  end

  def test_dial_by_name_round_trip_over_wss
    port = 8449
    public_url = "wss://localhost:#{port}/_hop"
    server = Hop::Endpoint.new
    server.on("acme/orders") { |req, reply| reply.call(201, req.args) }
    server.attach(port, Hop::DevTls.server_context, public_url) # WSS + well-known in one call

    client = Hop::Endpoint.new
    address = client.dial_by_name("https://localhost:#{port}", insecure_tls: true)
    assert_equal server.address, address
    status, body = client.request(address, "acme/orders", "create", "widget")
    assert_equal 201, status
    assert_equal "widget", body
  ensure
    server&.close
    client&.close
  end

  def test_cluster_join_and_quorum
    # DESIGN.md §40: cluster join + CP quorum bindings resolve against libhop and behave. The
    # cross-replica dedup + hold are proven in the Rust crate; here we exercise the Ruby surface.
    e = Hop::Endpoint.new(cluster: "shared-cluster-passphrase", quorum: 3)
    assert_equal 1, e.cluster_members
    assert_same e, e.cluster_quorum(2) # chainable
  ensure
    e&.close
  end
end
