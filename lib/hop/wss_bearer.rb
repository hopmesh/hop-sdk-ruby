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

    @seq = 60_000
    @seq_mutex = Mutex.new
    def self.next_link = @seq_mutex.synchronize { @seq += 1 }

    def self.accept_key(key) = Base64.strict_encode64(Digest::SHA1.digest(key + GUID))

    def self.encode_frame(payload, mask)
      n = payload.bytesize
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

    def self.read_exact(sock, n)
      return "".b if n.zero?

      data = sock.read(n)
      raise EOFError, "closed" unless data && data.bytesize == n

      data
    end

    def self.read_frame(sock)
      b0, b1 = read_exact(sock, 2).bytes
      opcode = b0 & 0x0F
      masked = (b1 & 0x80) != 0
      len = b1 & 0x7F
      len = read_exact(sock, 2).unpack1("n") if len == 126
      len = read_exact(sock, 8).unpack1("Q>") if len == 127
      mask = masked ? read_exact(sock, 4) : nil
      payload = read_exact(sock, len)
      payload = apply_mask(payload, mask) if mask
      [opcode, payload]
    end

    def self.run_link(endpoint, sock, role, mask)
      link = next_link
      send_fn = lambda do |buf|
        sock.write(encode_frame(buf, mask))
      rescue StandardError
        nil
      end
      endpoint.register_link(link, role, send_fn)
      loop do
        opcode, payload = read_frame(sock)
        break if opcode == 0x8

        endpoint.deliver(link, payload) if [0x2, 0x0].include?(opcode)
      end
    rescue EOFError, IOError, OpenSSL::SSL::SSLError, Errno::ECONNRESET
      nil
    ensure
      endpoint.link_down(link)
      begin
        sock.close
      rescue StandardError
        nil
      end
    end

    def self.serve(endpoint, port, ssl_context, public_url, ttl_secs = 3600)
      tcp = TCPServer.new(port)
      ssl_server = OpenSSL::SSL::SSLServer.new(tcp, ssl_context)
      # Let endpoint#close stop the listener so this accept loop exits instead of spinning on a closed
      # socket (accept on a closed server raises immediately, which without the break is a busy loop).
      endpoint.register_closer { ssl_server.close rescue nil }
      Thread.new do
        loop do
          sock = begin
            ssl_server.accept
          rescue StandardError
            break if tcp.closed?

            next
          end
          Thread.new { handle_conn(endpoint, sock, public_url, ttl_secs) }
        end
      end
      ssl_server
    end

    def self.handle_conn(endpoint, sock, public_url, ttl_secs)
      request_line = sock.gets
      return unless request_line

      _method, path, = request_line.split
      headers = {}
      while (line = sock.gets) && line != "\r\n"
        k, v = line.split(":", 2)
        headers[k.strip.downcase] = v.strip if v
      end

      if path == "/.well-known/hop"
        body = Hop::Discovery.well_known_body(endpoint, public_url, ttl_secs)
        sock.write("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: #{body.bytesize}\r\nconnection: close\r\n\r\n#{body}")
        sock.close
      elsif path == "/_hop" && headers["upgrade"]&.downcase == "websocket"
        sock.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: #{accept_key(headers["sec-websocket-key"])}\r\n\r\n")
        run_link(endpoint, sock, :acceptor, false)
      else
        sock.write("HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n")
        sock.close
      end
    rescue StandardError
      begin
        sock.close
      rescue StandardError
        nil
      end
    end

    def self.dial(endpoint, wss_url, insecure_tls: false)
      uri = URI.parse(wss_url)
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = insecure_tls ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
      sock = OpenSSL::SSL::SSLSocket.new(TCPSocket.new(uri.host, uri.port || 443), ctx)
      sock.hostname = uri.host
      sock.connect
      key = Base64.strict_encode64(Random.bytes(16))
      path = uri.path.to_s.empty? ? "/_hop" : uri.path
      sock.write("GET #{path} HTTP/1.1\r\nHost: #{uri.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: #{key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
      status = sock.gets
      raise "WS upgrade failed: #{status}" unless status&.include?("101")

      nil while (line = sock.gets) && line != "\r\n" # drain response headers
      endpoint.register_closer { sock.close rescue nil } # so endpoint#close ends run_link's read loop
      Thread.new { run_link(endpoint, sock, :dialer, true) }
      sock
    end
  end
end
