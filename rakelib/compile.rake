# frozen_string_literal: true

require "rake/clean"
require_relative "xcrypt_build"

# Mix Rake's sh/ruby helpers into XCryptBuild as module-level methods.
# This must happen before any task body runs (not before the file is loaded),
# so method definitions in xcrypt_build.rb may call sh freely.
module XCryptBuild
  extend Rake::FileUtilsExt
end

# ---------------------------------------------------------------------------
# Clean targets
# ---------------------------------------------------------------------------

CLEAN.include("tmp/")
CLOBBER.include("lib/xcrypt/*/")

# ---------------------------------------------------------------------------
# libxcrypt — native shared library
# ---------------------------------------------------------------------------

namespace :libxcrypt do
  desc "Build libxcrypt as a shared, position-independent library (native)"
  task :build do
    XCryptBuild.build_libxcrypt!(nil, host: nil, cc: nil, arch_flag: nil)
  end
end

# ---------------------------------------------------------------------------
# Native extension — current platform
# ---------------------------------------------------------------------------

file XCryptBuild::XCRYPT_LIB => "libxcrypt:build" do
  current_cfg = XCryptBuild::PLATFORMS.find { |_, v| v[:ffi_arch_os] == XCryptBuild::XCRYPT_ARCH_OS }&.last ||
                { ffi_arch_os: XCryptBuild::XCRYPT_ARCH_OS, arch_flag: nil, cc: nil, host: nil, dock: nil }
  XCryptBuild.link_xcrypt!(nil, current_cfg)
end

desc "Compile the XCrypt native extension (current platform)"
task compile: XCryptBuild::XCRYPT_LIB

# ---------------------------------------------------------------------------
# Cross-compilation — one task per platform
# ---------------------------------------------------------------------------

XCryptBuild::PLATFORMS.each do |platform_key, cfg|
  desc "Cross-compile XCrypt for #{platform_key}"
  task "compile:#{platform_key}" do
    XCryptBuild.build_libxcrypt!(platform_key, cfg)
    XCryptBuild.link_xcrypt!(platform_key, cfg)
  end
end
