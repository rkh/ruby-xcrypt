# frozen_string_literal: true

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
  require "xcrypt/yescrypt"

  # Raised when hashing or salt generation fails.  Common causes include an
  # unsupported algorithm, a malformed setting string, or a passphrase that
  # exceeds {FFI::CRYPT_MAX_PASSPHRASE_SIZE} bytes.
  Error ||= Class.new(StandardError)

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
  # setting directly from those parameters instead, delegating to
  # {XCrypt::Yescrypt}:
  #
  # * For +:yescrypt+ (and +:gost_yescrypt+): delegates to
  #   {XCrypt::Yescrypt.generate_setting}, producing a +$y$+ setting.
  #   +n+ must be a power of 2 greater than 1; +r+, +p+, +t+, and +flags+
  #   default to 8, 1, 0, and {XCrypt::Yescrypt::DEFAULTS} respectively.
  #
  # * For +:scrypt+: delegates to {XCrypt::Yescrypt.generate_scrypt_setting},
  #   producing a +$7$+ setting.  +n+ must be a power of 2 (2..2^63); +r+
  #   and +p+ default to 32 and 1.  +t+ and +flags+ are not used for scrypt.
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
  # @param flags [Integer, nil] yescrypt mode flags; see {XCrypt::Yescrypt}
  #   constants; yescrypt only; defaults to {XCrypt::Yescrypt::DEFAULTS}
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
        return Yescrypt.generate_setting(n: n || 4096, r: r || 8, p: p || 1,
                                         t: t || 0, flags: flags || Yescrypt::DEFAULTS)
      when :scrypt
        return Yescrypt.generate_scrypt_setting(n: n || 16384, r: r || 32, p: p || 1)
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
