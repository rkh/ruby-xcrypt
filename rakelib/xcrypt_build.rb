# frozen_string_literal: true

require "fileutils"
require "etc"
require "ffi"

# All compilation-related constants and helpers.  Rake's +sh+ is mixed in by
# compile.rake (via extend Rake::FileUtilsExt) before any task body runs, so
# method definitions here may call +sh+ freely.
module XCryptBuild
  # ---------------------------------------------------------------------------
  # Platform definitions
  #
  # ffi_arch_os  – subdirectory name used by the native loader at runtime
  # host         – autotools --host for cross-compilation (nil = native)
  # cc           – C compiler override (nil = system default / arch_flag only)
  # dock         – rake-compiler-dock platform name (nil = no Docker, macOS only)
  # arch_flag    – Clang/GCC architecture flag for macOS cross-compilation
  # ---------------------------------------------------------------------------

  PLATFORMS = {
    "x86_64-linux"  => {
      ffi_arch_os: "x86_64-linux",
      host:        "x86_64-linux-gnu",
      cc:          "x86_64-linux-gnu-gcc",
      dock:        "x86_64-linux",
      arch_flag:   nil,
    },
    "aarch64-linux" => {
      ffi_arch_os: "aarch64-linux",
      host:        "aarch64-linux-gnu",
      cc:          "aarch64-linux-gnu-gcc",
      dock:        "aarch64-linux",
      arch_flag:   nil,
    },
    "x86-linux"     => {
      ffi_arch_os: "i386-linux",
      host:        "i686-linux-gnu",
      cc:          "i686-linux-gnu-gcc",
      dock:        "x86-linux",
      arch_flag:   nil,
    },
    "arm-linux"     => {
      ffi_arch_os: "arm-linux",
      host:        "arm-linux-gnueabihf",
      cc:          "arm-linux-gnueabihf-gcc",
      dock:        "arm-linux",
      arch_flag:   nil,
    },
    "x86_64-darwin" => {
      ffi_arch_os: "x86_64-darwin",
      host:        nil,
      cc:          nil,
      dock:        nil,
      arch_flag:   "-arch x86_64",
    },
    "arm64-darwin"  => {
      ffi_arch_os: "aarch64-darwin",
      host:        nil,
      cc:          nil,
      dock:        nil,
      arch_flag:   "-arch arm64",
    },
  }.freeze

  LINUX_PLATFORMS  = PLATFORMS.select { |_, v| v[:dock] }.freeze
  DARWIN_PLATFORMS = PLATFORMS.reject { |_, v| v[:dock] }.freeze

  # ---------------------------------------------------------------------------
  # Constants
  # ---------------------------------------------------------------------------

  # Absolute path to the project root (one directory above rakelib/).
  ROOT = File.dirname(__dir__).freeze

  LIBXCRYPT_SRC_DIR = File.join(ROOT, "ext", "libxcrypt").freeze
  XCRYPT_ARCH_OS    = "#{::FFI::Platform::ARCH}-#{::FFI::Platform::OS}".freeze
  XCRYPT_LIB_EXT    = ::FFI::Platform.mac? ? "bundle" : "so"
  XCRYPT_LIB        = File.join("lib", "xcrypt", XCRYPT_ARCH_OS, "libxcrypt.#{XCRYPT_LIB_EXT}").freeze

  # ---------------------------------------------------------------------------
  # Path helpers
  # ---------------------------------------------------------------------------

  # Build directory for libxcrypt.  A nil platform means native (current host).
  def self.libxcrypt_build_dir(platform = nil)
    label = platform ? "-#{platform}" : ""
    File.join(ROOT, "tmp", "libxcrypt#{label}")
  end

  # Symlink that autotools creates pointing at the versioned shared library.
  def self.libxcrypt_shared(platform = nil)
    is_darwin = platform ? platform.include?("darwin") : ::FFI::Platform.mac?
    File.join(libxcrypt_build_dir(platform), ".libs", is_darwin ? "libcrypt.dylib" : "libcrypt.so")
  end

  def self.xcrypt_lib_dir(ffi_arch_os)
    File.join(ROOT, "lib", "xcrypt", ffi_arch_os)
  end

  def self.xcrypt_lib_path(ffi_arch_os)
    ext = ffi_arch_os.include?("darwin") ? "bundle" : "so"
    File.join(xcrypt_lib_dir(ffi_arch_os), "libxcrypt.#{ext}")
  end

  # Relative path used in gemspec file lists.
  def self.xcrypt_lib_rel(ffi_arch_os)
    ext = ffi_arch_os.include?("darwin") ? "bundle" : "so"
    "lib/xcrypt/#{ffi_arch_os}/libxcrypt.#{ext}"
  end

  # ---------------------------------------------------------------------------
  # Build helpers
  # ---------------------------------------------------------------------------

  def self.ensure_configure!
    return if File.exist?(File.join(LIBXCRYPT_SRC_DIR, "configure"))
    sh "autoreconf -fiv #{LIBXCRYPT_SRC_DIR}"
  end

  def self.build_libxcrypt!(platform_key, cfg)
    shared = libxcrypt_shared(platform_key)
    return if File.exist?(shared)

    ensure_configure!
    build_dir = libxcrypt_build_dir(platform_key)
    FileUtils.mkdir_p(build_dir)

    host_arg  = cfg[:host]      ? "--host=#{cfg[:host]}" : ""
    cc_arg    = cfg[:cc]        ? "CC=#{cfg[:cc]}"       : ""
    arch_flag = cfg[:arch_flag] || ""
    cflags    = ["-fPIC", "-O2", arch_flag].reject(&:empty?).join(" ")

    sh <<~SH
      cd #{build_dir} && \
      #{LIBXCRYPT_SRC_DIR}/configure \
        --enable-shared \
        --disable-static \
        --disable-obsolete-api \
        #{host_arg} \
        #{cc_arg} \
        CFLAGS='#{cflags}'
    SH
    sh "make -C #{build_dir} -j#{Etc.nprocessors}"
  end

  # Copy libxcrypt's shared library to the gem's lib directory.
  # On macOS, rewrite the embedded install name so it loads correctly from
  # wherever the gem is installed.
  def self.link_xcrypt!(platform_key, cfg)
    ffi_arch_os = cfg[:ffi_arch_os]
    lib_path    = xcrypt_lib_path(ffi_arch_os)
    src         = libxcrypt_shared(platform_key)

    FileUtils.mkdir_p(xcrypt_lib_dir(ffi_arch_os))
    FileUtils.cp(File.realpath(src), lib_path)

    if ffi_arch_os.include?("darwin")
      sh "install_name_tool -id @loader_path/#{File.basename(lib_path)} #{lib_path}"
    end
  end

  # Generate a platform-specific gemspec for a precompiled gem.
  def self.platform_gemspec_content(platform_key, ffi_arch_os)
    lib_rel = xcrypt_lib_rel(ffi_arch_os)
    <<~RUBY
      # frozen_string_literal: true
      # AUTO-GENERATED — do not edit; produced by rake gem:native:#{platform_key}

      spec          = Gem::Specification.load(File.expand_path("xcrypt.gemspec", __dir__))
      spec.platform = #{platform_key.inspect}
      spec.files    = Dir["lib/**/*.rb"] + [#{lib_rel.inspect}]
      spec.extensions.clear
      spec
    RUBY
  end
end
