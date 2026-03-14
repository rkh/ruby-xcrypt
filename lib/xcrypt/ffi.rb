# frozen_string_literal: true

require "ffi"

module XCrypt
  # Low-level FFI bindings for libxcrypt.
  #
  # Consumers should use the high-level {XCrypt} module methods instead of
  # calling into this module directly.
  #
  # The shared library loaded here is built from the libxcrypt submodule
  # (ext/libxcrypt).  Run <tt>bundle exec rake compile</tt> to build it
  # before loading this gem.
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

    # Load the shared library built from the libxcrypt submodule.
    # It lives in a platform-specific subdirectory next to this file.
    begin
      _ext     = ::FFI::Platform.mac? ? "bundle" : "so"
      _lib     = File.expand_path(
        "../#{::FFI::Platform::ARCH}-#{::FFI::Platform::OS}/libxcrypt.#{_ext}",
        __FILE__
      )
      ffi_lib _lib
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

    # yescrypt_params_t — parameter struct for yescrypt_encode_params_r.
    #
    # Mirrors the C struct:
    #   typedef struct {
    #     yescrypt_flags_t flags;  /* uint32_t */
    #     uint64_t N;
    #     uint32_t r, p, t, g;
    #     uint64_t NROM;
    #   } yescrypt_params_t;
    #
    # FFI automatically inserts the 4-byte padding needed to align N to 8 bytes.
    class YescryptParams < ::FFI::Struct
      layout :flags, :uint32,
             :N,     :uint64,
             :r,     :uint32,
             :p,     :uint32,
             :t,     :uint32,
             :g,     :uint32,
             :NROM,  :uint64
    end

    # uint8_t *yescrypt_encode_params_r(const yescrypt_params_t *params,
    #                                   const uint8_t *src, size_t srclen,
    #                                   uint8_t *buf, size_t buflen)
    #
    # Generates a $y$ setting string from explicit yescrypt parameters and
    # a caller-supplied raw salt (src/srclen).  Returns NULL on error.
    #
    # libxcrypt renames this symbol to _crypt_yescrypt_encode_params_r via a
    # #define in crypt-port.h, so that is the actual exported symbol name.
    attach_function :yescrypt_encode_params_r,
                    :_crypt_yescrypt_encode_params_r,
                    [:pointer, :pointer, :size_t, :pointer, :size_t],
                    :pointer
  end

  private_constant :FFI
end
