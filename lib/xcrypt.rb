# frozen_string_literal: true

module XCrypt
  require "xcrypt/version"
  require "xcrypt/ffi"

  Error ||= Class.new(StandardError)

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

  ALGORITHMS.each_key do |algorithm|
    define_method(algorithm) do |phrase, setting = nil, cost: nil|
      if setting
        setting_algorithm = detect_algorithm(setting)
        if setting_algorithm != algorithm
          raise ArgumentError, "setting algorithm #{setting_algorithm.inspect} does not match expected #{algorithm.inspect}"
        end
      end
      crypt(phrase, setting, algorithm:, cost:)
    end
  end

  def algorithms = ALGORITHMS.keys

  def detect_algorithm(setting) = PREFIXES[setting[/\A\$\w+\$?|_/].to_s]

  def crypt(phrase, setting = nil, algorithm: nil, cost: nil)
    setting, algorithm = nil, setting if setting.is_a? Symbol
    setting ||= generate_setting(algorithm, cost:)
    data = ::FFI::MemoryPointer.new(:uint8, FFI::CRYPT_DATA_SIZE)
    result_ptr = FFI.crypt_rn(phrase, setting, data, FFI::CRYPT_DATA_SIZE)
    raise Error, "crypt failed: invalid setting or unsupported algorithm" if result_ptr.null?
    result_ptr.read_string
  ensure
    data&.clear
  end

  def verify(phrase, hash)
    return false if hash.nil? || hash.empty? || hash.start_with?("*")
    result = crypt(phrase, hash)
    secure_compare(result, hash)
  rescue Error
    false
  end

  def generate_setting(algorithm = nil, cost: nil)
    prefix = ALGORITHMS.fetch(algorithm) { raise ArgumentError, "unknown algorithm: #{algorithm.inspect}" } if algorithm
    cost ||= 0

    output = ::FFI::MemoryPointer.new(:char, FFI::CRYPT_GENSALT_OUTPUT_SIZE)
    result_ptr = FFI.crypt_gensalt_rn(prefix, cost, nil, 0, output, FFI::CRYPT_GENSALT_OUTPUT_SIZE)
    raise Error, "crypt_gensalt failed: unknown prefix or unsupported algorithm" if result_ptr.null?

    result_ptr.read_string
  end

  private

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
