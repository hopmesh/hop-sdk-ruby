# frozen_string_literal: true

# The WSS Internet bearer for a Ruby endpoint, in pure stdlib (no gems): a minimal RFC 6455 WebSocket
# (Upgrade handshake + binary framing) over the stdlib socket + OpenSSL. The server also answers GET
# /.well-known/hop on the same port, so attach wires both. core does the Noise + crypto over the frame
# payloads; one drained packet is one binary WS message. IO buffering (gets then read) cleanly
# separates the HTTP handshake from the frame stream, so a header read never over-consumes frame bytes.
require "socket"
require "openssl"
require "digest/sha1"
require "base64"
require "uri"
require "hop/discovery"

module Hop
  module WssBearer
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    MAX_MESSAGE_BYTES = 1 << 20
    MAX_FRAME_BYTES = MAX_MESSAGE_BYTES
    MAX_HEADER_BYTES = 16 << 10
    MAX_PENDING_CONNECTIONS = 64
    HANDSHAKE_WORKERS = 4
    HANDSHAKE_TIMEOUT_S = 5.0
    READ_TIMEOUT_S = 15.0

    @seq = 60_000
    @seq_mutex = Mutex.new
    def self.next_link = @seq_mutex.synchronize { @seq += 1 }

    def self.accept_key(key) = Base64.strict_encode64(Digest::SHA1.digest(key + GUID))

    def self.encode_frame(payload, mask)
      n = payload.bytesize
      raise ArgumentError, "WebSocket message exceeds 1 MiB" if n > MAX_MESSAGE_BYTES

      header = (+"\x82").b # FIN + binary opcode
      mb = mask ? 0x80 : 0
      if n < 126
        header << (mb | n).chr
      elsif n < 65_536
        header << (mb | 126).chr << [n].pack("n")
      else
        header << (mb | 127).chr << [n].pack("Q>")
      end
      if mask
        mk = Random.bytes(4)
        header << mk << apply_mask(payload, mk)
      else
        header << payload
      end
      header
    end

    def self.apply_mask(data, mask)
      out = data.dup.b
      out.bytesize.times { |i| out.setbyte(i, out.getbyte(i) ^ mask.getbyte(i % 4)) }
      out
    end

    def self.monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    def self.wait_io(sock, readable, deadline)
      remaining = deadline - monotonic
      raise IOError, "socket deadline exceeded" unless remaining.positive?

      io = sock.respond_to?(:to_io) ? sock.to_io : sock
      ready = readable ? IO.select([io], nil, nil, remaining) : IO.select(nil, [io], nil, remaining)
      raise IOError, "socket deadline exceeded" unless ready
    end

    def self.read_some(sock, n, deadline)
      return sock.read(n) unless sock.respond_to?(:read_nonblock)

      loop do
        result = sock.read_nonblock(n, exception: false)
        case result
        when :wait_readable then wait_io(sock, true, deadline)
        when :wait_writable then wait_io(sock, false, deadline)
        else return result
        end
      end
    end

    def self.write_all(sock, data, timeout = HANDSHAKE_TIMEOUT_S)
      return sock.write(data) unless sock.respond_to?(:write_nonblock)

      deadline = monotonic + timeout
      offset = 0
      while offset < data.bytesize
        result = sock.write_nonblock(data.byteslice(offset..), exception: false)
        case result
        when :wait_readable then wait_io(sock, true, deadline)
        when :wait_writable then wait_io(sock, false, deadline)
        else offset += result
        end
      end
      offset
    end

    def self.read_exact(sock, n, deadline: monotonic + READ_TIMEOUT_S)
      return "".b if n.zero?

      data = +"".b
      while data.bytesize < n
        chunk = read_some(sock, n - data.bytesize, deadline)
        raise EOFError, "closed" unless chunk

        data << chunk
      end
      data
    end

    def self.read_frame_part(sock, remaining = MAX_MESSAGE_BYTES, deadline: monotonic + READ_TIMEOUT_S)
      b0, b1 = read_exact(sock, 2, deadline: deadline).bytes
      raise IOError, "WebSocket extensions are not supported" unless (b0 & 0x70).zero?

      final = (b0 & 0x80) != 0
      opcode = b0 & 0x0F
      masked = (b1 & 0x80) != 0
      len = b1 & 0x7F
      len = read_exact(sock, 2, deadline: deadline).unpack1("n") if len == 126
      len = read_exact(sock, 8, deadline: deadline).unpack1("Q>") if len == 127
      raise IOError, "WebSocket message exceeds 1 MiB" if len > remaining || len > MAX_MESSAGE_BYTES
      raise IOError, "invalid WebSocket control frame" if opcode >= 0x8 && (!final || len > 125)

      mask = masked ? read_exact(sock, 4, deadline: deadline) : nil
      payload = read_exact(sock, len, deadline: deadline)
      payload = apply_mask(payload, mask) if mask
      [final, opcode, payload]
    end

    def self.read_frame(sock)
      _final, opcode, payload = read_frame_part(sock)
      [opcode, payload]
    end

    def self.read_message(sock)
      deadline = monotonic + READ_TIMEOUT_S
      final, opcode, payload = read_frame_part(sock, deadline: deadline)
      return [opcode, payload] if opcode >= 0x8
      raise IOError, "expected a binary WebSocket message" unless opcode == 0x2
      return [opcode, payload] if final

      parts = [payload]
      total = payload.bytesize
      until final
        final, continuation, payload = read_frame_part(sock, MAX_MESSAGE_BYTES - total, deadline: deadline)
        raise IOError, "expected a WebSocket continuation frame" unless continuation.zero?

        total += payload.bytesize
        parts << payload
      end
      [opcode, parts.join]
    end

    def self.run_link(endpoint, sock, role, mask)
      link = next_link
      send_fn = lambda do |buf|
        write_all(sock, encode_frame(buf, mask), READ_TIMEOUT_S)
      rescue StandardError
        nil
      end
      endpoint.register_link(link, role, send_fn)
      loop do
        opcode, payload = read_message(sock)
        break if opcode == 0x8

        endpoint.deliver(link, payload) if opcode == 0x2
      end
    rescue EOFError, IOError, OpenSSL::SSL::SSLError, SystemCallError
      nil
    ensure
      endpoint.link_down(link)
      begin
        sock.close
      rescue StandardError
        nil
      end
    end

    class Admission
      def initialize(limit)
        @limit = limit
        @lock = Mutex.new
        @sockets = {}
      end

      def acquire(sock)
        @lock.synchronize do
          return nil if @sockets.size >= @limit

          lease = SocketLease.new(self, sock)
          @sockets[lease] = sock
          lease
        end
      end

      def replace(lease, sock)
        @lock.synchronize { @sockets[lease] = sock if @sockets.key?(lease) }
      end

      def release(lease)
        @lock.synchronize { @sockets.delete(lease) }
      end

      def close_all
        sockets = @lock.synchronize { @sockets.values.dup }
        sockets.each { |sock| sock.close rescue nil }
      end

      def count = @lock.synchronize { @sockets.size }
    end

    class SocketLease
      attr_reader :sock

      def initialize(admission, sock)
        @admission = admission
        @sock = sock
        @lock = Mutex.new
        @released = false
      end

      def replace(sock)
        @sock = sock
        @admission.replace(self, sock)
      end

      def release
        @lock.synchronize do
          return if @released

          @released = true
          @admission.release(self)
        end
      end

      def close = (@sock.close rescue nil)
    end

    def self.ssl_accept(raw, ssl_context)
      sock = OpenSSL::SSL::SSLSocket.new(raw, ssl_context)
      sock.sync_close = true
      deadline = monotonic + HANDSHAKE_TIMEOUT_S
      loop do
        result = sock.accept_nonblock(exception: false)
        case result
        when :wait_readable then wait_io(sock, true, deadline)
        when :wait_writable then wait_io(sock, false, deadline)
        else return sock
        end
      end
    rescue StandardError
      sock&.close rescue nil
      raise
    end

    def self.read_http_head(sock)
      deadline = monotonic + HANDSHAKE_TIMEOUT_S
      data = +"".b
      until data.include?("\r\n\r\n")
        room = MAX_HEADER_BYTES + 1 - data.bytesize
        chunk = read_some(sock, [4096, room].min, deadline)
        raise EOFError, "closed" unless chunk

        data << chunk
        raise IOError, "HTTP headers exceed 16 KiB" if data.bytesize > MAX_HEADER_BYTES
      end
      head, rest = data.split("\r\n\r\n", 2)
      lines = head.split("\r\n")
      request = lines.shift&.split(" ", 3)
      raise IOError, "malformed HTTP request line" unless request&.size == 3

      headers = {}
      lines.each do |line|
        key, value = line.split(":", 2)
        headers[key.strip.downcase] = value.strip if value
      end
      [request[0], request[1], headers, rest.to_s.b]
    end

    def self.serve(endpoint, port, ssl_context, public_url, ttl_secs = 3600)
      tcp = TCPServer.new(port)
      tcp.listen(MAX_PENDING_CONNECTIONS)
      pending = SizedQueue.new(MAX_PENDING_CONNECTIONS)
      admission = Admission.new(MAX_PENDING_CONNECTIONS)
      closing = false
      close_lock = Mutex.new

      close_server = lambda do
        close_lock.synchronize do
          next if closing

          closing = true
          tcp.close rescue nil
          admission.close_all
          pending.close
        end
      end
      endpoint.register_closer(&close_server)

      HANDSHAKE_WORKERS.times do |i|
        Thread.new do
          Thread.current.name = "hop-wss-handshake-#{i}" if Thread.current.respond_to?(:name=)
          loop do
            break if close_lock.synchronize { closing && pending.empty? }

            lease = pending.pop
            break unless lease

            transferred = false
            begin
              sock = ssl_accept(lease.sock, ssl_context)
              lease.replace(sock)
              transferred = handle_conn(endpoint, sock, public_url, ttl_secs, lease)
            rescue StandardError
              nil
            ensure
              unless transferred
                lease.close
                lease.release
              end
            end
          end
        end
      end

      Thread.new do
        loop do
          raw = tcp.accept
          lease = admission.acquire(raw)
          unless lease
            raw.close rescue nil
            next
          end
          begin
            pending.push(lease, true)
          rescue ThreadError
            lease.close
            lease.release
          end
        rescue IOError, Errno::EBADF
          break
        rescue StandardError
          next unless close_lock.synchronize { closing }

          break
        end
      end
      tcp
    end

    def self.handle_conn(endpoint, sock, public_url, ttl_secs, lease = nil)
      _method, path, headers, rest = read_http_head(sock)
      if path == "/.well-known/hop"
        body = Hop::Discovery.well_known_body(endpoint, public_url, ttl_secs)
        write_all(sock, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: #{body.bytesize}\r\nconnection: close\r\n\r\n#{body}")
        false
      elsif path == "/_hop" && headers["upgrade"]&.downcase == "websocket"
        key = headers["sec-websocket-key"] or raise IOError, "missing Sec-WebSocket-Key"
        write_all(sock, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: #{accept_key(key)}\r\n\r\n")
        buffered = BufferedSocket.new(sock, rest)
        if lease
          Thread.new do
            begin
              run_link(endpoint, buffered, :acceptor, false)
            ensure
              lease.release
            end
          end
          true
        else
          run_link(endpoint, buffered, :acceptor, false)
          false
        end
      else
        write_all(sock, "HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n")
        false
      end
    end

    class BufferedSocket
      def initialize(sock, initial)
        @sock = sock
        @buffer = initial
      end

      def read_nonblock(n, exception: true)
        unless @buffer.empty?
          chunk = @buffer.byteslice(0, n)
          @buffer = @buffer.byteslice(chunk.bytesize..) || "".b
          return chunk
        end
        @sock.read_nonblock(n, exception: exception)
      end

      def write_nonblock(data, exception: true) = @sock.write_nonblock(data, exception: exception)
      def to_io = @sock.to_io
      def close = @sock.close
    end

    def self.dial(endpoint, wss_url, insecure_tls: false)
      uri = URI.parse(wss_url)
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = insecure_tls ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
      raw = TCPSocket.new(uri.host, uri.port || 443, connect_timeout: HANDSHAKE_TIMEOUT_S)
      sock = OpenSSL::SSL::SSLSocket.new(raw, ctx)
      sock.sync_close = true
      sock.hostname = uri.host
      deadline = monotonic + HANDSHAKE_TIMEOUT_S
      loop do
        result = sock.connect_nonblock(exception: false)
        case result
        when :wait_readable then wait_io(sock, true, deadline)
        when :wait_writable then wait_io(sock, false, deadline)
        else break
        end
      end
      key = Base64.strict_encode64(Random.bytes(16))
      path = uri.path.to_s.empty? ? "/_hop" : uri.path
      write_all(sock, "GET #{path} HTTP/1.1\r\nHost: #{uri.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: #{key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
      _version, status, _headers, rest = read_http_response(sock)
      raise "WS upgrade failed: #{status}" unless status&.include?("101")

      endpoint.register_closer { sock.close rescue nil } # so endpoint#close ends run_link's read loop
      Thread.new { run_link(endpoint, BufferedSocket.new(sock, rest), :dialer, true) }
      sock
    end

    def self.read_http_response(sock)
      deadline = monotonic + HANDSHAKE_TIMEOUT_S
      data = +"".b
      until data.include?("\r\n\r\n")
        room = MAX_HEADER_BYTES + 1 - data.bytesize
        chunk = read_some(sock, [4096, room].min, deadline)
        raise EOFError, "closed" unless chunk

        data << chunk
        raise IOError, "HTTP headers exceed 16 KiB" if data.bytesize > MAX_HEADER_BYTES
      end
      head, rest = data.split("\r\n\r\n", 2)
      lines = head.split("\r\n")
      status = lines.shift.to_s
      [status.split(" ", 2).first, status, lines, rest.to_s.b]
    end
  end
end
