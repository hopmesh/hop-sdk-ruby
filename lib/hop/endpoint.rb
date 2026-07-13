# frozen_string_literal: true

require "monitor"
require "timeout"
require "hop/ffi"

module Hop
  # An inbound service request. `from` is the cryptographically verified sender identity (base58).
  Request = Struct.new(:from, :from_bytes, :service, :method, :args) do
    def text = args
  end

  # Receive Hop messages in Ruby with a Sinatra/Rails-shaped surface, over the libhop C ABI.
  #
  #   hop = Hop::Endpoint.new
  #   hop.on("acme/orders") { |req, reply| reply.call(201, "ok") }  # req.from is VERIFIED
  #
  # Semantics: inbound is a durable store-and-forward consume; a reply is a new addressed message that
  # may arrive later. The DX is HTTP-shaped; delivery is delay-tolerant. core is poll-model, so the
  # endpoint runs a background pump thread (the node is thread-safe).
  class Endpoint
    def initialize(key: nil, tick_ms: 50)
      Hop::FFI.assert_abi!
      @node = key ? Hop::FFI.node_with_secret(key) : Hop::FFI.node_new
      Hop::FFI.tick(@node, now_ms)
      Hop::FFI.publish_prekey(@node)
      @handlers = {}
      @links = {}
      @pending = {}
      @closers = []
      @mutex = Mutex.new         # guards @pending
      @node_lock = Monitor.new   # serializes every libhop call on @node vs. #close; reentrant so a
      @closed = false            # reply issued from inside #pump re-enters without deadlocking
      @thread = Thread.new { pump_loop(tick_ms / 1000.0) }
    end

    def address = Hop::FFI.to_b58(address_bytes)
    def address_bytes = with_node { |n| Hop::FFI.address(n) }

    # Register a receiver for a hops:// service. The block gets (req, reply); reply is a callable
    # reply.call(status, body).
    def on(service, &block)
      with_node { |n| Hop::FFI.subscribe(n, service) }
      @handlers[service] = block
      self
    end

    # Call a service on a remote endpoint. Blocks until the response returns (delay-tolerant).
    def request(dst, service, method, args = "", timeout: 15.0)
      dst_bytes = dst.is_a?(String) && dst.bytesize == 32 ? dst : Hop::FFI.from_b58(dst)
      q = Queue.new
      # Send and register the waiter atomically under @node_lock so #pump (which also holds it) cannot
      # deliver the response before @pending knows to route it.
      req_id = with_node do |n|
        id = Hop::FFI.send_service_request(n, dst_bytes, service, method, to_bytes(args))
        @mutex.synchronize { @pending[id] = q }
        id
      end
      raise "endpoint is closed" unless req_id

      begin
        Timeout.timeout(timeout) { q.pop } # [status, body]
      rescue Timeout::Error
        @mutex.synchronize { @pending.delete(req_id) }
        raise "hops://#{service}/#{method} timed out after #{timeout}s"
      end
    end

    # Sign a self-certifying reachability record for this endpoint's address bound to `endpoint`.
    def sign_reach(endpoint, ttl_secs = 3600) = with_node { |n| Hop::FFI.sign_reach(n, endpoint, ttl_secs) }

    # Start an HTTPS server (WSS bearer at /_hop + /.well-known/hop) IN ONE CALL. `public_url` is where
    # senders reach it, e.g. "wss://myaddress.com/_hop". Returns the server (call #shutdown to stop).
    def attach(port, ssl_context, public_url, ttl_secs: 3600)
      require "hop/wss_bearer"
      Hop::WssBearer.serve(self, port, ssl_context, public_url, ttl_secs)
    end

    # Resolve a base HTTPS URL to a verified endpoint, dial its WSS, and return the reachable address
    # (then use #request). Set insecure_tls: true only for a dev/self-signed cert.
    def dial_by_name(base_url, insecure_tls: false)
      require "hop/discovery"
      require "hop/wss_bearer"
      info = Hop::Discovery.resolve(base_url, insecure_tls: insecure_tls)
      Hop::WssBearer.dial(self, info[:wss_url], insecure_tls: insecure_tls)
      info[:address]
    end

    # Register a teardown hook (e.g. a bearer's listening socket). #close runs these before freeing the
    # node so bearer threads unblock and exit. If already closed, the hook fires immediately.
    def register_closer(&block)
      run_now = @node_lock.synchronize { @closed ? true : (@closers << block; false) }
      block.call if run_now
    end

    # ---- bearer seam (called from bearer threads) ----
    def register_link(link, role, send_fn)
      with_node do |n|
        @links[link] = send_fn
        Hop::FFI.connected(n, link, role == :dialer)
      end
    end

    def deliver(link, data) = with_node { |n| Hop::FFI.received(n, link, data) }

    def link_down(link)
      with_node do |n|
        @links.delete(link)
        Hop::FFI.disconnected(n, link)
      end
    end

    def close
      @node_lock.synchronize do
        return if @closed

        @closed = true
      end
      @closers.each { |c| c.call rescue nil } # unblock bearer accept/read threads so they exit
      @thread.join(1)
      # Free only after @closed is set and the pump has stopped: a late bearer-thread call (a WSS
      # run_link firing #link_down as its socket EOFs) now short-circuits in #with_node instead of
      # dereferencing a freed node.
      @node_lock.synchronize do
        next unless @node

        Hop::FFI.node_free(@node)
        @node = nil
      end
    end

    private

    def now_ms = (Time.now.to_f * 1000).to_i
    def to_bytes(v) = v.is_a?(String) ? v.b : v.to_s.b

    # Run a libhop call on the node under the reentrant lock, unless the endpoint has been closed (in
    # which case @node may already be freed, so we must not touch it). Returns nil when closed.
    def with_node
      @node_lock.synchronize do
        return nil if @closed

        yield @node
      end
    end

    def pump_loop(dt)
      until @closed
        begin
          pump
        rescue StandardError => e
          warn "hop pump error: #{e}"
        end
        sleep(dt)
      end
    end

    def pump
      with_node do |n|
        Hop::FFI.tick(n, now_ms)
        Hop::FFI.drain_outgoing(n).each { |link, data| (fn = @links[link]) && fn.call(data) }
        Hop::FFI.take_service_requests(n).each do |frm, rid, service, method, args|
          handler = @handlers[service]
          next unless handler

          req = Request.new(Hop::FFI.to_b58(frm), frm, service, method, args)
          reply = ->(status, body = "") { with_node { |nn| Hop::FFI.send_service_response(nn, frm, rid, status, to_bytes(body)) } }
          handler.call(req, reply)
        end
        Hop::FFI.take_service_responses(n).each do |_frm, for_id, status, body|
          q = @mutex.synchronize { @pending.delete(for_id) }
          q&.push([status, body])
        end
      end
    end
  end
end
