# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name        = "hop-endpoint"
  spec.version     = "0.0.1"
  spec.summary     = "Embeddable Hop mesh endpoint for Ruby (Sinatra/Rails-shaped) over the libhop C ABI"
  spec.description = "Receive Hop messages in Ruby with a hop.on / reply surface, over libhop via Fiddle. " \
                     "Your service becomes directly reachable on the mesh, no relay. Zero gems (stdlib only)."
  spec.authors     = ["Jason Waldrip"]
  spec.homepage    = "https://hopme.sh"
  spec.license     = "Apache-2.0"

  spec.required_ruby_version = ">= 3.0"

  spec.files       = Dir["lib/**/*.rb", "README.md", "CLAUDE.md"]
  spec.require_paths = ["lib"]

  # Runtime deps: none. Fiddle, OpenSSL, Socket, Net::HTTP, JSON, Base64, Digest are all stdlib.
  # libhop itself is a native library located at load time via HOP_LIBDIR or target/{debug,release}.
  spec.metadata = { "rubygems_mfa_required" => "true" }
end
