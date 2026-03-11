# frozen_string_literal: true

require "ffi"
require "ffi-compiler/loader"

module XCrypt
  # Low-level FFI bindings for libxcrypt.
  #
  # Consumers should use the high-level {XCrypt} module methods instead of
  # calling into this module directly.
  #
  # The shared library loaded here is compiled from the libxcrypt submodule
  # (ext/libxcrypt) via ffi-compiler.  Run <tt>bundle exec rake compile</tt>
  # to build it before loading this gem.
  module FFI
    extend ::FFI::Library

    # Size constants mirrored from <crypt.h>.
    CRYPT_OUTPUT_SIZE         = 384
    CRYPT_MAX_PASSPHRASE_SIZE = 512
    CRYPT_GENSALT_OUTPUT_SIZE = 192
    CRYPT_DATA_RESERVED_SIZE  = 767
    CRYPT_DATA_INTERNAL_SIZE  = 30_720

    # sizeof(struct crypt_data) == 32768 bytes, as guaranteed by the header.
    CRYPT_DATA_SIZE = 32_768

    # crypt_checksalt(3) return codes.
    CRYPT_SALT_OK              = 0
    CRYPT_SALT_INVALID         = 1
    CRYPT_SALT_METHOD_DISABLED = 2
    CRYPT_SALT_METHOD_LEGACY   = 3
    CRYPT_SALT_TOO_CHEAP       = 4

    # Load the native extension compiled from the libxcrypt submodule.
    # FFI::Compiler::Loader searches for lib<arch>-<os>/libxcrypt.{bundle,so}
    # relative to this file's location.
    begin
      ffi_lib ::FFI::Compiler::Loader.find("xcrypt")
    rescue LoadError
      raise LoadError,
            "XCrypt native extension not found. " \
            "Build it with: rake compile"
    end

    # char *crypt_rn(const char *phrase, const char *setting,
    #                void *data, int size)
    #
    # Thread-safe variant that writes to a caller-supplied buffer.  Returns
    # NULL on error instead of a magic error string.
    attach_function :crypt_rn, [:string, :string, :pointer, :int], :pointer

    # char *crypt_gensalt_rn(const char *prefix, unsigned long count,
    #                        const char *rbytes, int nrbytes,
    #                        char *output, int output_size)
    #
    # Thread-safe salt generator that writes to a caller-supplied buffer.
    # Pass NULL for rbytes to let the library obtain entropy from the OS.
    attach_function :crypt_gensalt_rn,
                    [:string, :ulong, :pointer, :int, :pointer, :int],
                    :pointer

    # int crypt_checksalt(const char *setting)
    #
    # Inspects a setting string and reports whether it is valid.
    attach_function :crypt_checksalt, [:string], :int

    # const char *crypt_preferred_method(void)
    #
    # Returns the prefix string of the library's preferred (strongest)
    # hashing method.
    attach_function :crypt_preferred_method, [], :string
  end

  private_constant :FFI
end
