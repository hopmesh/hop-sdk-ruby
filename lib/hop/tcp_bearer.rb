# frozen_string_literal: true

require "socket"

module Hop
  # The raw-TCP Internet bearer: opaque Hop frames over TCP, core does the Noise. TCP is a stream, so
  # each drained packet is length-prefixed (4-byte big-endian) and reassembled on the far side.
  module TcpBearer
    MAX_FRAME_BYTES = 1 << 20
    @seq = 40_000
    @seq_mutex = Mutex.new
    def self.next_link = @seq_mutex.synchronize { @seq += 1 }

    def self.send_framed(sock, buf)
      sock.write([buf.bytesize].pack("N") + buf)
    rescue IOError, Errno::EPIPE, Errno::ECONNRESET, Errno::EBADF
      nil
    end

    def self.read_exact(sock, n)
      data = +"".b
      while data.bytesize < n
        chunk = sock.read(n - data.bytesize)
        return nil unless chunk

        data << chunk
      end
      data
    end

    def self.recv_loop(endpoint, sock, link)
      loop do
        hdr = read_exact(sock, 4)
        break unless hdr

        n = hdr.unpack1("N")
        break if n > MAX_FRAME_BYTES
        frame = n.zero? ? "".b : read_exact(sock, n)
        break unless frame

        endpoint.deliver(link, frame)
      end
    rescue IOError, Errno::ECONNRESET, Errno::EBADF
      nil
    ensure
      endpoint.link_down(link)
      begin
        sock.close
      rescue StandardError
        nil
      end
    end

    def self.listen(endpoint, port, host: "0.0.0.0")
      server = TCPServer.new(host, port)
      sockets = {}
      sockets_mutex = Mutex.new
      closing = false
      endpoint.register_closer do
        sockets_mutex.synchronize do
          closing = true
          server.close rescue nil
          sockets.each_key { |socket| socket.close rescue nil }
        end
      end
      Thread.new do
        loop do
          sock = begin
            server.accept
          rescue StandardError
            break
          end
          reject = sockets_mutex.synchronize do
            if closing
              true
            else
              sockets[sock] = true
              false
            end
          end
          if reject
            sock.close rescue nil
            next
          end
          link = next_link
          endpoint.register_link(link, :acceptor, ->(buf) { send_framed(sock, buf) })
          Thread.new do
            recv_loop(endpoint, sock, link)
            sockets_mutex.synchronize { sockets.delete(sock) }
          end
        end
      end
      server
    end

    def self.dial(endpoint, host, port)
      sock = TCPSocket.new(host, port)
      link = next_link
      endpoint.register_link(link, :dialer, ->(buf) { send_framed(sock, buf) })
      endpoint.register_closer { sock.close rescue nil }
      Thread.new { recv_loop(endpoint, sock, link) }
      sock
    end
  end
end
