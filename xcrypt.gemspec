# frozen_string_literal: true

require_relative "lib/xcrypt/version"

Gem::Specification.new do |spec|
  spec.name        = "xcrypt"
  spec.version     = XCrypt::VERSION
  spec.summary     = "Ruby FFI bindings for libxcrypt"
  spec.author      = "Konstantin Haase"
  spec.email       = "ruby-xcrypt@rkh.im"
  spec.license     = "MIT"
  spec.homepage    = "https://github.com/rkh/ruby-xcrypt"
  spec.description = <<~DESC
    Ruby FFI bindings for libxcrypt, a modern library for one-way hashing of
    passwords.  Supports yescrypt, bcrypt, SHA-512, SHA-256, and other
    algorithms provided by the bundled libxcrypt source (ext/libxcrypt).
  DESC

  spec.files = Dir["lib/**/*.rb"] +
               Dir["ext/xcrypt/**/*.c"] +
               Dir["ext/libxcrypt/{lib,doc,test}/**/*"].reject { |f| File.directory?(f) } +
               Dir["ext/libxcrypt/build-aux/m4/**/*.m4"] +
               Dir["ext/libxcrypt/build-aux/scripts/**/*"].reject { |f| File.directory?(f) } +
               %w[
                 ext/libxcrypt/configure.ac
                 ext/libxcrypt/Makefile.am
                 ext/libxcrypt/autogen.sh
                 ext/libxcrypt/COPYING.LIB
                 ext/libxcrypt/LICENSING
                 ext/libxcrypt/AUTHORS
                 ext/libxcrypt/ChangeLog
                 ext/libxcrypt/NEWS
                 ext/libxcrypt/README
                 ext/libxcrypt/README.md
                 ext/libxcrypt/THANKS
               ]

  spec.require_paths = ["lib"]
  spec.extensions    = ["Rakefile"]

  spec.required_ruby_version = ">= 3.0"

  spec.add_dependency "ffi",          "~> 1.0"
  spec.add_dependency "ffi-compiler", "~> 1.0"
  spec.add_dependency "rake",         "~> 13.0"

  spec.metadata["source_code_uri"] = "https://github.com/rkh/ruby-xcrypt"
end
