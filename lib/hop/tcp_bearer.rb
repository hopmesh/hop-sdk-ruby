# frozen_string_literal: true

require "socket"

module Hop
  # The raw-TCP Internet bearer: opaque Hop frames over TCP, core does the Noise. TCP is a stream, so
  # each drained packet is length-prefixed (4-byte big-endian) and reassembled on the far side.
  module TcpBearer
    @seq = 40_000
    @seq_mutex = Mutex.new
    def self.next_link = @seq_mutex.synchronize { @seq += 1 }

    def self.send_framed(sock, buf)
      sock.write([buf.bytesize].pack("N") + buf)
    rescue IOError, Errno::EPIPE, Errno::ECONNRESET, Errno::EBADF
      nil
    end

    def self.recv_loop(endpoint, sock, link)
      loop do
        hdr = sock.read(4)
        break unless hdr

        n = hdr.unpack1("N")
        frame = n.zero? ? "".b : sock.read(n)
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
      Thread.new do
        loop do
          sock = begin
            server.accept
          rescue StandardError
            break
          end
          link = next_link
          endpoint.register_link(link, :acceptor, ->(buf) { send_framed(sock, buf) })
          Thread.new { recv_loop(endpoint, sock, link) }
        end
      end
      server
    end

    def self.dial(endpoint, host, port)
      sock = TCPSocket.new(host, port)
      link = next_link
      endpoint.register_link(link, :dialer, ->(buf) { send_framed(sock, buf) })
      Thread.new { recv_loop(endpoint, sock, link) }
      sock
    end
  end
end
