# frozen_string_literal: true

require "securerandom"

module XCrypt
  # Setting-string generation for the yescrypt and scrypt algorithms.
  #
  # Both algorithms share a base-64 alphabet and encoding scheme taken from
  # libxcrypt's +alg-yescrypt-common.c+.  The public methods produce setting
  # strings that can be passed directly to {XCrypt.crypt}.
  #
  # @example Generate a $y$ yescrypt setting
  #   setting = XCrypt::Yescrypt.generate_setting(n: 16384, r: 8, p: 1)
  #   hash = XCrypt.crypt("hunter2", setting)
  #
  # @example Generate a $7$ scrypt setting
  #   setting = XCrypt::Yescrypt.generate_scrypt_setting(n: 16384, r: 32, p: 1)
  #   hash = XCrypt.crypt("hunter2", setting)
  module Yescrypt
    extend self

    # -------------------------------------------------------------------------
    # Flag constants — mirrors alg-yescrypt.h
    #
    # These may be OR'd together to form the +flags:+ argument of
    # {generate_setting}, except that {WORM} stands alone (do not combine
    # with {RW}).
    # -------------------------------------------------------------------------

    # Classic scrypt with minimal extensions (t parameter support only).
    WORM     = 0x001

    # Full yescrypt mode — time-memory tradeoff resistant.
    RW       = 0x002

    # Number of inner rounds.
    ROUNDS_3 = 0x000
    ROUNDS_6 = 0x004

    # Memory-access gather width.
    GATHER_1 = 0x000
    GATHER_2 = 0x008
    GATHER_4 = 0x010
    GATHER_8 = 0x018

    # Simple mix factor.
    SIMPLE_1 = 0x000
    SIMPLE_2 = 0x020
    SIMPLE_4 = 0x040
    SIMPLE_8 = 0x060

    # S-box size.
    SBOX_6K   = 0x000
    SBOX_12K  = 0x080
    SBOX_24K  = 0x100
    SBOX_48K  = 0x180
    SBOX_96K  = 0x200
    SBOX_192K = 0x280
    SBOX_384K = 0x300
    SBOX_768K = 0x380

    # Recommended defaults: RW mode with 6 rounds, 4-wide gather, 2x simple
    # mix, and a 12 KiB S-box.
    DEFAULTS = RW | ROUNDS_6 | GATHER_4 | SIMPLE_2 | SBOX_12K

    # -------------------------------------------------------------------------
    # Public interface
    # -------------------------------------------------------------------------

    # Generates a +$y$+ yescrypt setting string from explicit parameters.
    #
    # Implements the encoding of libxcrypt's +yescrypt_encode_params_r+
    # (alg-yescrypt-common.c) in pure Ruby, because that function is not
    # exported on Linux.
    #
    # @param n [Integer] memory/CPU cost; must be a power of 2 greater than 1
    # @param r [Integer] block size (default: 8)
    # @param p [Integer] parallelism (default: 1)
    # @param t [Integer] additional time cost (default: 0)
    # @param flags [Integer] yescrypt mode flags; see +WORM+/+RW+/+ROUNDS_*+
    #   etc.; defaults to {DEFAULTS}
    # @return [String] a +$y$+ setting string
    # @raise [ArgumentError] if +n+ is not a valid power of 2, or if +flags+
    #   is an unsupported combination
    def generate_setting(n:, r: 8, p: 1, t: 0, flags: DEFAULTS)
      n_log2 = log2_of_power_of_2(n)

      # Compute the "flavor" field exactly as yescrypt_encode_params_r does:
      #   flags < RW       → flavor = flags  (WORM / pure-scrypt modes)
      #   flags is valid RW → flavor = RW + (flags >> 2)
      flavor =
        if flags < RW
          flags
        elsif (flags & 0x3) == RW && flags <= (RW | 0x3fc)
          RW + (flags >> 2)
        else
          raise ArgumentError, "invalid yescrypt flags: 0x#{flags.to_s(16)}"
        end

      # "have" bitmask indicates which optional fields follow r.
      have = 0
      have |= 1 if p != 1
      have |= 2 if t != 0

      setting = +"$y$"
      setting << encode_varint(flavor, 0)
      setting << encode_varint(n_log2, 1)
      setting << encode_varint(r, 1)
      if have != 0
        setting << encode_varint(have, 1)
        setting << encode_varint(p, 2) if p != 1
        setting << encode_varint(t, 1) if t != 0
      end
      setting << "$"
      setting << encode_bytes(SecureRandom.random_bytes(32))
      setting
    end

    # Generates a +$7$+ scrypt setting string from explicit parameters.
    #
    # Encodes the setting using the same base-64 alphabet and field layout as
    # libxcrypt's +gensalt_scrypt_rn+ (crypt-scrypt.c).
    #
    # @param n [Integer] memory/CPU cost; must be a power of 2 greater than 1
    # @param r [Integer] block size (default: 32)
    # @param p [Integer] parallelism (default: 1)
    # @return [String] a +$7$+ setting string
    # @raise [ArgumentError] if +n+ is not a valid power of 2
    def generate_scrypt_setting(n:, r: 32, p: 1)
      n_log2 = log2_of_power_of_2(n)

      setting = +"$7$"
      setting << B64[n_log2]
      setting << encode_uint32(r, 30)
      setting << encode_uint32(p, 30)
      setting << encode_bytes(SecureRandom.random_bytes(32))
      setting
    end

    private

    # Base-64 alphabet shared by yescrypt and scrypt (crypt-style, not RFC 4648).
    B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    # Returns log2(n) after validating that n is a power of 2 greater than 1.
    def log2_of_power_of_2(n)
      n_log2 = Integer(Math.log2(n).round)
      raise ArgumentError, "n must be a power of 2 greater than 1 (got #{n})" unless (1 << n_log2) == n && n > 1
      n_log2
    end

    # Variable-length base-64 encoding for yescrypt parameter fields
    # (encode64_uint32 in alg-yescrypt-common.c, last argument = min).
    #
    # The first character of the output encodes both the number of subsequent
    # characters and the most-significant bits.  The character ranges used are:
    #   1 char : indices  0..47  (48 distinct values)
    #   2 chars: indices 48..56  (9 × 64 = 576 additional values)
    #   3 chars: indices 57..60  (4 × 64² = 16 384 additional values), …
    def encode_varint(src, min)
      raise ArgumentError, "value #{src} is below minimum #{min}" if src < min

      src -= min
      start = 0
      endv  = 47
      chars = 1
      bits  = 0

      loop do
        count = (endv + 1 - start) << bits
        break if src < count
        raise ArgumentError, "value too large for yescrypt varint encoding" if start >= 63

        start = endv + 1
        endv  = start + (62 - endv) / 2
        src  -= count
        chars += 1
        bits  += 6
      end

      result = +B64[start + (src >> bits)]
      (chars - 1).times { bits -= 6; result << B64[(src >> bits) & 0x3f] }
      result
    end

    # Fixed-width base-64 encoding of a 32-bit value using +srcbits+ bits,
    # LSB first (ceil(srcbits/6) output characters).
    # Used for scrypt's r and p fields (encode64_uint32 in crypt-scrypt.c).
    def encode_uint32(value, srcbits)
      out = +""
      bits = 0
      while bits < srcbits
        out << B64[value & 0x3f]
        value >>= 6
        bits += 6
      end
      out
    end

    # Encodes a binary string using the fixed-width base-64 scheme, processing
    # 3 bytes (24 bits) into 4 characters at a time (encode64 in both
    # alg-yescrypt-common.c and crypt-scrypt.c).
    def encode_bytes(bytes)
      out = +""
      i   = 0
      while i < bytes.bytesize
        value = 0
        bits  = 0
        while bits < 24 && i < bytes.bytesize
          value |= bytes.getbyte(i) << bits
          bits += 8
          i    += 1
        end
        out << encode_uint32(value, bits)
      end
      out
    end
  end
end
