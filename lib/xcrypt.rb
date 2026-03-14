# frozen_string_literal: true

require "securerandom"

# Top-level module providing a high-level Ruby interface to libxcrypt, a
# modern library for one-way hashing of passwords.
#
# All public methods are available directly on the module.
# The most common entry points are the algorithm-specific convenience methods
# ({yescrypt}, {bcrypt}, {sha512}, etc.) and {verify}.
#
# @example Hash a password with yescrypt (the strongest supported algorithm)
#   hash = XCrypt.yescrypt("correct horse battery staple")
#   XCrypt.verify("correct horse battery staple", hash) #=> true
#
# @example Hash with an explicit cost factor
#   hash = XCrypt.bcrypt("hunter2", cost: 12)
#
# @example Use the generic interface
#   hash = XCrypt.crypt("hunter2", algorithm: :sha512)
#
# @example Generate a yescrypt setting with explicit N, r, p, t, and flags
#   setting = XCrypt.generate_setting(:yescrypt, n: 16384, r: 8, p: 1, t: 0,
#                                     flags: XCrypt::YESCRYPT_DEFAULTS)
#   hash = XCrypt.crypt("hunter2", setting)
#
# @example Generate a scrypt ($7$) setting with explicit N, r, p
#   setting = XCrypt.generate_setting(:scrypt, n: 16384, r: 32, p: 1)
#   hash = XCrypt.crypt("hunter2", setting)
module XCrypt
  require "xcrypt/version"
  require "xcrypt/ffi"

  # Raised when hashing or salt generation fails.  Common causes include an
  # unsupported algorithm, a malformed setting string, or a passphrase that
  # exceeds {FFI::CRYPT_MAX_PASSPHRASE_SIZE} bytes.
  Error ||= Class.new(StandardError)

  # ---------------------------------------------------------------------------
  # Yescrypt flag constants (mirrors alg-yescrypt.h)
  # ---------------------------------------------------------------------------
  #
  # These flags control which variant of yescrypt is used when generating a
  # setting with an explicit +flags:+ parameter.  They may be OR'd together
  # except that +YESCRYPT_WORM+ stands alone (do not combine with
  # +YESCRYPT_RW+).
  #
  # @see generate_setting

  # Classic scrypt with minimal extensions (t parameter support only).
  YESCRYPT_WORM     = 0x001

  # Full yescrypt mode — time-memory tradeoff resistant.
  YESCRYPT_RW       = 0x002

  # Number of inner rounds flavors.
  YESCRYPT_ROUNDS_3 = 0x000
  YESCRYPT_ROUNDS_6 = 0x004

  # Memory-access gather width.
  YESCRYPT_GATHER_1 = 0x000
  YESCRYPT_GATHER_2 = 0x008
  YESCRYPT_GATHER_4 = 0x010
  YESCRYPT_GATHER_8 = 0x018

  # Simple mix factor.
  YESCRYPT_SIMPLE_1 = 0x000
  YESCRYPT_SIMPLE_2 = 0x020
  YESCRYPT_SIMPLE_4 = 0x040
  YESCRYPT_SIMPLE_8 = 0x060

  # S-box size.
  YESCRYPT_SBOX_6K   = 0x000
  YESCRYPT_SBOX_12K  = 0x080
  YESCRYPT_SBOX_24K  = 0x100
  YESCRYPT_SBOX_48K  = 0x180
  YESCRYPT_SBOX_96K  = 0x200
  YESCRYPT_SBOX_192K = 0x280
  YESCRYPT_SBOX_384K = 0x300
  YESCRYPT_SBOX_768K = 0x380

  # Recommended defaults: RW mode with 6 rounds, 4-wide gather, 2x simple mix,
  # and a 12 KiB S-box.
  YESCRYPT_DEFAULTS = YESCRYPT_RW | YESCRYPT_ROUNDS_6 |
                      YESCRYPT_GATHER_4 | YESCRYPT_SIMPLE_2 | YESCRYPT_SBOX_12K

  # Maps each supported algorithm name to its setting-string prefix.
  #
  # The prefix is the leading characters of any hash produced by that
  # algorithm and is used to identify the algorithm from an existing hash.
  #
  # @return [Hash{Symbol => String}]
  ALGORITHMS = {
    yescrypt:      "$y$",
    gost_yescrypt: "$gy$",
    scrypt:        "$7$",
    bcrypt:        "$2b$",
    sha512:        "$6$",
    sha256:        "$5$",
    sha1:          "$sha1$",
    sun_md5:       "$md5",
    md5:           "$1$",
    bsdi_des:      "_",
    des:           "",
  }.freeze

  PREFIXES = ALGORITHMS.invert.freeze
  private_constant :ALGORITHMS, :PREFIXES

  extend self

  # @!method yescrypt(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using yescrypt, the strongest supported algorithm.
  #   @param phrase [String] the password to hash
  #   @param setting [String, nil] an existing hash or salt string to use as
  #     the setting; a new setting is generated automatically when +nil+
  #   @param cost [Integer, nil] work-factor override; uses the library
  #     default when +nil+
  #   @return [String] the hashed password
  #   @raise [ArgumentError] if +setting+ belongs to a different algorithm
  #   @raise [Error] if hashing fails

  # @!method gost_yescrypt(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using GOST R 34.11-2012 combined with yescrypt.
  #   @param (see #yescrypt)
  #   @return (see #yescrypt)
  #   @raise (see #yescrypt)

  # @!method scrypt(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using scrypt.
  #   @param (see #yescrypt)
  #   @return (see #yescrypt)
  #   @raise (see #yescrypt)

  # @!method bcrypt(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using bcrypt (Blowfish-based password hashing).
  #   @param (see #yescrypt)
  #   @return (see #yescrypt)
  #   @raise (see #yescrypt)

  # @!method sha512(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using SHA-512 crypt.
  #   @param (see #yescrypt)
  #   @return (see #yescrypt)
  #   @raise (see #yescrypt)

  # @!method sha256(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using SHA-256 crypt.
  #   @param (see #yescrypt)
  #   @return (see #yescrypt)
  #   @raise (see #yescrypt)

  # @!method sha1(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using HMAC-SHA1 NetBSD crypt.
  #   @param (see #yescrypt)
  #   @return (see #yescrypt)
  #   @raise (see #yescrypt)

  # @!method sun_md5(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using SunMD5 (Solaris MD5 crypt).
  #   @param (see #yescrypt)
  #   @return (see #yescrypt)
  #   @raise (see #yescrypt)

  # @!method md5(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using MD5 crypt.
  #   @param (see #yescrypt)
  #   @return (see #yescrypt)
  #   @raise (see #yescrypt)

  # @!method bsdi_des(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using BSDi extended DES crypt.
  #   @param (see #yescrypt)
  #   @return (see #yescrypt)
  #   @raise (see #yescrypt)

  # @!method des(phrase, setting = nil, cost: nil)
  #   Hash +phrase+ using traditional DES crypt.
  #   @param (see #yescrypt)
  #   @return (see #yescrypt)
  #   @raise (see #yescrypt)

  ALGORITHMS.each_key do |algorithm|
    define_method(algorithm) do |phrase, setting = nil, cost: nil, n: nil, r: nil, p: nil, t: nil, flags: nil|
      if setting
        setting_algorithm = detect_algorithm(setting)
        if setting_algorithm != algorithm
          raise ArgumentError, "setting algorithm #{setting_algorithm.inspect} does not match expected #{algorithm.inspect}"
        end
      end
      crypt(phrase, setting, algorithm:, cost:, n:, r:, p:, t:, flags:)
    end
  end

  # Returns the names of all supported algorithms.
  #
  # @return [Array<Symbol>] algorithm names in order from strongest to weakest
  def algorithms = ALGORITHMS.keys

  # Detects which algorithm produced a given setting or hash string by
  # matching its leading prefix against {ALGORITHMS}.
  #
  # @param setting [String] a setting string or an existing password hash
  # @return [Symbol, nil] the algorithm name, or +nil+ if the prefix is
  #   unrecognized
  def detect_algorithm(setting) = PREFIXES[setting[/\A\$\w+\$?|_/].to_s]

  # Hashes +phrase+ using libxcrypt's +crypt_rn+ function.
  #
  # When both +setting+ and +algorithm+ are omitted, a fresh setting is
  # generated with the library's default algorithm.  The result is always a
  # self-describing string whose leading prefix identifies the algorithm and
  # encodes the salt, making it safe to store directly.
  #
  # @param phrase [String] the password to hash
  # @param setting [String, Symbol, nil] an existing hash or salt string, or
  #   an algorithm +Symbol+ as shorthand for passing only +algorithm:+;
  #   generates a fresh setting when +nil+
  # @param algorithm [Symbol, nil] algorithm to use when generating a new
  #   setting; ignored when +setting+ is already a String
  # @param cost [Integer, nil] work-factor override passed to
  #   {generate_setting}; uses the library default when +nil+
  # @param n [Integer, nil] explicit N parameter for yescrypt/scrypt; passed
  #   to {generate_setting} when no +setting+ is provided
  # @param r [Integer, nil] explicit r parameter; passed to {generate_setting}
  # @param p [Integer, nil] explicit p parameter; passed to {generate_setting}
  # @param t [Integer, nil] explicit t parameter (yescrypt only); passed to
  #   {generate_setting}
  # @param flags [Integer, nil] explicit yescrypt flags; passed to
  #   {generate_setting}
  # @return [String] the hashed password
  # @raise [Error] if +crypt_rn+ returns +NULL+, indicating an invalid
  #   setting or an unsupported algorithm
  def crypt(phrase, setting = nil, algorithm: nil, cost: nil, n: nil, r: nil, p: nil, t: nil, flags: nil)
    setting, algorithm = nil, setting if setting.is_a? Symbol
    setting ||= generate_setting(algorithm, cost:, n:, r:, p:, t:, flags:)
    data = ::FFI::MemoryPointer.new(:uint8, FFI::CRYPT_DATA_SIZE)
    result_ptr = FFI.crypt_rn(phrase, setting, data, FFI::CRYPT_DATA_SIZE)
    raise Error, "crypt failed: invalid setting or unsupported algorithm" if result_ptr.null?
    result_ptr.read_string
  ensure
    data&.clear
  end

  # Verifies that +phrase+ matches a previously computed +hash+.
  #
  # Returns +false+ immediately for any hash value that would cause
  # libxcrypt to return a magic failure token (strings beginning with +"*"+),
  # or for empty or +nil+ input, guarding against invalid-hash oracle attacks.
  # The final comparison is performed in constant time to prevent timing
  # attacks.
  #
  # @param phrase [String] the candidate password
  # @param hash [String, nil] the stored password hash to verify against
  # @return [Boolean] +true+ if +phrase+ matches +hash+, +false+ otherwise
  def verify(phrase, hash)
    return false if hash.nil? || hash.empty? || hash.start_with?("*")
    result = crypt(phrase, hash)
    secure_compare(result, hash)
  rescue Error
    false
  end

  # Generates a fresh setting string suitable for passing to {crypt}.
  #
  # When only +algorithm+ and optionally +cost+ are given, delegates to
  # libxcrypt's +crypt_gensalt_rn+, which draws entropy from the OS.
  #
  # When +n+, +r+, +p+, +t+, or +flags+ are supplied the method generates the
  # setting directly from those parameters instead:
  #
  # * For +:yescrypt+ (and +:gost_yescrypt+): calls +yescrypt_encode_params_r+
  #   with a {YESCRYPT_DEFAULTS}-flagged struct, producing a +$y$+ setting.
  #   +n+ must be a power of 2 greater than 1; +r+, +p+, +t+, and +flags+
  #   default to 8, 1, 0, and {YESCRYPT_DEFAULTS} respectively.
  #
  # * For +:scrypt+: encodes the +$7$+ setting directly in Ruby using the same
  #   base-64 alphabet and field layout as libxcrypt's +gensalt_scrypt_rn+.
  #   +n+ must be a power of 2 (2..2^63); +r+ and +p+ default to 32 and 1.
  #   The +t+ and +flags+ parameters are not used for scrypt.
  #
  # When +algorithm+ is +nil+, the library selects its preferred algorithm.
  #
  # @param algorithm [Symbol, nil] the desired algorithm; uses the library
  #   default when +nil+
  # @param cost [Integer, nil] work-factor for the generated setting; a value
  #   of +0+ selects the library's own default cost; ignored when +n:+ is set
  # @param n [Integer, nil] explicit N (memory/CPU cost, must be a power of 2
  #   greater than 1); yescrypt and scrypt only
  # @param r [Integer, nil] block size parameter; yescrypt and scrypt only
  # @param p [Integer, nil] parallelism parameter; yescrypt and scrypt only
  # @param t [Integer, nil] additional time cost; yescrypt only
  # @param flags [Integer, nil] yescrypt mode flags; see +YESCRYPT_*+ constants;
  #   yescrypt only; defaults to {YESCRYPT_DEFAULTS}
  # @return [String] a setting string beginning with the algorithm prefix
  # @raise [ArgumentError] if +algorithm+ is not a key in {ALGORITHMS}, or if
  #   +n+ is not a power of 2 greater than 1
  # @raise [Error] if the underlying C call returns +NULL+
  def generate_setting(algorithm = nil, cost: nil, n: nil, r: nil, p: nil, t: nil, flags: nil)
    if algorithm
      ALGORITHMS.key?(algorithm) or raise ArgumentError, "unknown algorithm: #{algorithm.inspect}"
    end

    if n || r || p || t || flags
      case algorithm
      when :yescrypt, :gost_yescrypt, nil
        return generate_yescrypt_setting(n: n || 4096, r: r || 8, p: p || 1,
                                         t: t || 0, flags: flags || YESCRYPT_DEFAULTS)
      when :scrypt
        return generate_scrypt_setting(n: n || 16384, r: r || 32, p: p || 1)
      else
        raise ArgumentError,
              "n/r/p/t/flags parameters are only supported for :yescrypt and :scrypt, got #{algorithm.inspect}"
      end
    end

    prefix = ALGORITHMS[algorithm]
    cost ||= 0

    output = ::FFI::MemoryPointer.new(:char, FFI::CRYPT_GENSALT_OUTPUT_SIZE)
    result_ptr = FFI.crypt_gensalt_rn(prefix, cost, nil, 0, output, FFI::CRYPT_GENSALT_OUTPUT_SIZE)
    raise Error, "crypt_gensalt failed: unknown prefix or unsupported algorithm" if result_ptr.null?

    result_ptr.read_string
  end

  private

  # Base-64 alphabet shared by yescrypt and scrypt (crypt-style, not RFC 4648).
  CRYPT_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  private_constant :CRYPT_B64

  # Calls +yescrypt_encode_params_r+ with a freshly generated random salt to
  # produce a +$y$+ setting string.
  #
  # @raise [ArgumentError] if +n+ is not a power of 2 greater than 1
  # @raise [Error] if the C call fails
  def generate_yescrypt_setting(n:, r:, p:, t:, flags:)
    n_log2 = Integer(Math.log2(n).round)
    raise ArgumentError, "n must be a power of 2 greater than 1 (got #{n})" unless (1 << n_log2) == n && n > 1

    salt = SecureRandom.random_bytes(32)

    params = FFI::YescryptParams.new
    params[:flags] = flags
    params[:N]     = n
    params[:r]     = r
    params[:p]     = p
    params[:t]     = t
    params[:g]     = 0
    params[:NROM]  = 0

    salt_ptr = ::FFI::MemoryPointer.new(:uint8, salt.bytesize)
    salt_ptr.put_bytes(0, salt)

    output = ::FFI::MemoryPointer.new(:char, FFI::CRYPT_GENSALT_OUTPUT_SIZE)
    result_ptr = FFI.yescrypt_encode_params_r(
      params.pointer, salt_ptr, salt.bytesize, output, FFI::CRYPT_GENSALT_OUTPUT_SIZE
    )
    raise Error, "yescrypt_encode_params_r failed: invalid parameters" if result_ptr.null?

    result_ptr.read_string
  end

  # Builds a +$7$+ scrypt setting string directly, using the same base-64
  # encoding as libxcrypt's +gensalt_scrypt_rn+.
  #
  # Format: $7$ + ascii64[N_log2] + encode64_uint32(r,30) + encode64_uint32(p,30) + encode64(salt)
  #
  # @raise [ArgumentError] if +n+ is not a power of 2 greater than 1
  def generate_scrypt_setting(n:, r:, p:)
    n_log2 = Integer(Math.log2(n).round)
    raise ArgumentError, "n must be a power of 2 greater than 1 (got #{n})" unless (1 << n_log2) == n && n > 1

    salt = SecureRandom.random_bytes(32)

    setting = +"$7$"
    setting << CRYPT_B64[n_log2]
    setting << scrypt_encode_uint32(r, 30)
    setting << scrypt_encode_uint32(p, 30)
    setting << scrypt_encode_bytes(salt)
    setting
  end

  # Encodes +value+ in the scrypt/yescrypt base-64 alphabet using +bits+ bits,
  # LSB first (ceil(bits/6) output characters).
  def scrypt_encode_uint32(value, bits)
    out = +""
    bit = 0
    while bit < bits
      out << CRYPT_B64[value & 0x3f]
      value >>= 6
      bit += 6
    end
    out
  end

  # Encodes +bytes+ (a binary String) in the scrypt/yescrypt base-64 alphabet,
  # processing 3 input bytes (24 bits) into 4 output characters at a time.
  def scrypt_encode_bytes(bytes)
    out = +""
    i = 0
    while i < bytes.bytesize
      value = 0
      bits  = 0
      while bits < 24 && i < bytes.bytesize
        value |= bytes.getbyte(i) << bits
        bits += 8
        i += 1
      end
      out << scrypt_encode_uint32(value, bits)
    end
    out
  end

  # Compares two strings in constant time to prevent timing attacks.
  #
  # Pads or truncates +trusted+ to match +untrusted+'s byte length before
  # comparing so that the number of loop iterations is always the same
  # regardless of content.  A separate length check at the end ensures that a
  # length-padded match is still rejected.
  #
  # Uses {OpenSSL.fixed_length_secure_compare} when available (Ruby >= 2.7
  # with openssl >= 2.2); otherwise falls back to a pure-Ruby XOR loop.
  #
  # @param trusted [String] the known-good value (e.g., the output of {crypt})
  # @param untrusted [String] the value supplied by the caller
  # @return [Boolean] +true+ only when both strings are identical
  def secure_compare(trusted, untrusted)
    return false unless trusted.respond_to?   :to_str and trusted = trusted.to_str.b
    return false unless untrusted.respond_to? :to_str and untrusted = untrusted.to_str.b

    # avoid ability for attacker to guess length of string by timing attack
    comparable = trusted[0, untrusted.bytesize].ljust(untrusted.bytesize, "\0".b)

    result = defined?(OpenSSL.fixed_length_secure_compare) ?
      OpenSSL.fixed_length_secure_compare(comparable, untrusted) :
      comparable.each_byte.zip(untrusted.each_byte).reduce(0) { |acc, (a, b)| acc | (a ^ b) }.zero?

    trusted.bytesize == untrusted.bytesize and result
  end
end
