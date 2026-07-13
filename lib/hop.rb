# frozen_string_literal: true

# Receive Hop messages in Ruby: an embeddable endpoint over the libhop C ABI (via Fiddle, zero gems).
require "hop/ffi"
require "hop/endpoint"
require "hop/tcp_bearer"

module Hop
  # Wire two endpoints directly (in-process bearer), no sockets. Proves the ergonomics end to end.
  def self.connect_in_process(a, b, la: 11, lb: 22)
    a.register_link(la, :dialer, ->(buf) { b.deliver(lb, buf) })
    b.register_link(lb, :acceptor, ->(buf) { a.deliver(la, buf) })
  end
end
