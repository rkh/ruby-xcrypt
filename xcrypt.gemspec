# frozen_string_literal: true

require_relative "lib/xcrypt/version"

Gem::Specification.new do |spec|
  spec.name        = "xcrypt"
  spec.version     = XCrypt::VERSION
  spec.summary     = "Ruby FFI bindings for libxcrypt"
  spec.description = <<~DESC
    Ruby FFI bindings for libxcrypt, a modern library for one-way hashing of
    passwords.  Supports yescrypt, bcrypt, SHA-512, SHA-256, and other
    algorithms provided by the bundled libxcrypt source (ext/libxcrypt).
  DESC

  spec.authors  = ["Konstantin Haase"]
  spec.license  = "MIT"

  spec.files = Dir["lib/**/*.rb"] +
               Dir["ext/xcrypt/**/*.c"] +
               Dir["ext/libxcrypt/**/*"].reject { |f| File.directory?(f) }

  spec.require_paths = ["lib"]
  spec.extensions    = ["Rakefile"]

  spec.required_ruby_version = ">= 3.0"

  spec.add_dependency "ffi",          "~> 1.0"
  spec.add_dependency "ffi-compiler", "~> 1.0"

  spec.metadata["source_code_uri"] = "https://github.com/rkh/ruby-xcrypt"
end
