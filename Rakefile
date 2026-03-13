# frozen_string_literal: true

require "rake/clean"
require "ffi"

task default: [:compile, :test]

if FFI::Platform.mac?
  task default: "test:linux"
end
