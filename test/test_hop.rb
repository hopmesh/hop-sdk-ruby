# frozen_string_literal: true

require "minitest/autorun"
require "hop"
require "hop/discovery"
require "hop/dev_tls"
require "hop/tcp_bearer"
require "hop/wss_bearer"
require "stringio"

class TestHop < Minitest::Test
  def test_every_fixed_width_argument_requires_exactly_32_bytes
    node = Hop::FFI.node_new
    Hop::FFI.tick(node, 1)
    exact = Hop::FFI.address(node)
    [0, 1, 31, 33].each do |size|
      invalid = "x".b * size
      calls = [
        -> { Hop::FFI.accept_inbox(node, invalid) },
        -> { Hop::FFI.cluster_join(node, invalid) },
        -> { Hop::FFI.send_service_request(node, invalid, "svc", "get", "".b) },
        -> { Hop::FFI.send_service_response(node, invalid, exact, 200, "".b) },
        -> { Hop::FFI.send_service_response(node, exact, invalid, 200, "".b) },
        -> { Hop::FFI.to_b58(invalid) },
        -> { Hop::Endpoint.new(key: invalid) }
      ]
      calls.each { |call| assert_raises(ArgumentError, &call) }
    end

    refute Hop::FFI.accept_inbox(node, exact)
    Hop::FFI.cluster_join(node, exact)
    assert_equal 32, Hop::FFI.send_service_request(node, exact, "svc", "get", "".b).bytesize
    assert Hop::FFI.send_service_response(node, exact, exact, 200, "".b)
    refute_empty Hop::FFI.to_b58(exact)
    keyed = Hop::Endpoint.new(key: exact, tick_ms: 1000)
    keyed.close
  ensure
    Hop::FFI.node_free(node) if node
  end

  def test_wss_frame_cap_rejects_header_without_body
    header = "\x82\x7f".b + [Hop::WssBearer::MAX_FRAME_BYTES + 1].pack("Q>")
    assert_raises(IOError) { Hop::WssBearer.read_frame(StringIO.new(header)) }
  end

  def test_wss_fragmented_cap_is_enforced_before_continuation_body
    half = Hop::WssBearer::MAX_MESSAGE_BYTES / 2
    first = ws_frame(false, 0x2, "a".b * (half + 1))
    oversized_continuation_header = ws_header(true, 0x0, half)
    assert_raises(IOError) do
      Hop::WssBearer.read_message(StringIO.new(first + oversized_continuation_header))
    end
  end

  def test_wss_fragmented_message_at_cap_materializes_once
    half = Hop::WssBearer::MAX_MESSAGE_BYTES / 2
    wire = ws_frame(false, 0x2, "a".b * half) + ws_frame(true, 0x0, "b".b * half)
    opcode, payload = Hop::WssBearer.read_message(StringIO.new(wire))
    assert_equal 0x2, opcode
    assert_equal Hop::WssBearer::MAX_MESSAGE_BYTES, payload.bytesize
    assert_equal "a", payload.byteslice(0)
    assert_equal "b", payload.byteslice(-1)
  end

  def test_wss_header_and_admission_caps_recover_idempotently
    oversized = "GET /_hop HTTP/1.1\r\nX-Fill: #{'x' * Hop::WssBearer::MAX_HEADER_BYTES}"
    assert_raises(IOError) { Hop::WssBearer.read_http_head(StringIO.new(oversized)) }

    admission = Hop::WssBearer::Admission.new(Hop::WssBearer::MAX_PENDING_CONNECTIONS)
    sockets = Array.new(Hop::WssBearer::MAX_PENDING_CONNECTIONS) { Object.new }
    sockets.each { |sock| sock.define_singleton_method(:close) {} }
    leases = sockets.map { |sock| admission.acquire(sock) }
    assert leases.all?
    assert_nil admission.acquire(Object.new), "cap+1 must be rejected"
    assert_equal Hop::WssBearer::MAX_PENDING_CONNECTIONS, admission.count
    leases.first.release
    leases.first.release
    replacement = admission.acquire(Object.new)
    refute_nil replacement, "cleanup must restore exactly one permit"
    replacement.release
    leases.drop(1).each(&:release)
    assert_equal 0, admission.count
  end

  def test_tcp_frame_cap_rejects_header_without_body
    endpoint = Object.new
    endpoint.define_singleton_method(:deliver) { raise "oversized frame delivered" }
    endpoint.define_singleton_method(:link_down) { |_| }
    reader, writer = Socket.pair(:UNIX, :STREAM, 0)
    thread = Thread.new { Hop::TcpBearer.recv_loop(endpoint, reader, 1) }
    writer.write([Hop::TcpBearer::MAX_FRAME_BYTES + 1].pack("N"))
    assert thread.join(1), "oversized frame left receiver blocked waiting for its body"
  ensure
    reader&.close rescue nil
    writer&.close rescue nil
  end

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

    # A raw TCP peer that never starts TLS and a malformed TLS request occupy/fail workers without
    # blocking the fixed acceptor pool or killing its next worker.
    stalled = TCPSocket.new("127.0.0.1", port)
    malformed_raw = TCPSocket.new("127.0.0.1", port)
    malformed_ctx = OpenSSL::SSL::SSLContext.new
    malformed_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    malformed = OpenSSL::SSL::SSLSocket.new(malformed_raw, malformed_ctx)
    malformed.sync_close = true
    malformed.hostname = "localhost"
    malformed.connect
    malformed.write("malformed\r\n\r\n")
    malformed.close

    client = Hop::Endpoint.new
    address = client.dial_by_name("https://localhost:#{port}", insecure_tls: true)
    assert_equal server.address, address
    status, body = client.request(address, "acme/orders", "create", "widget")
    assert_equal 201, status
    assert_equal "widget", body
  ensure
    stalled&.close rescue nil
    malformed&.close rescue nil
    server&.close
    client&.close
  end

  def test_cluster_join_and_quorum
    # Cluster join + TTL visibility threshold bindings resolve against libhop and behave. The
    # cross-replica dedup + hold are proven in the Rust crate; here we exercise the Ruby surface.
    e = Hop::Endpoint.new(cluster: "shared-cluster-passphrase", quorum: 3)
    assert_equal 1, e.cluster_members
    assert_same e, e.cluster_quorum(2) # chainable
  ensure
    e&.close
  end


  private

  def ws_header(final, opcode, len)
    first = (final ? 0x80 : 0) | opcode
    if len < 126
      [first, len].pack("CC")
    elsif len < 65_536
      [first, 126, len].pack("CCn")
    else
      [first, 127].pack("CC") + [len].pack("Q>")
    end
  end

  def ws_frame(final, opcode, payload)
    ws_header(final, opcode, payload.bytesize) + payload
  end
end
