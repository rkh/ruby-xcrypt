# frozen_string_literal: true

require "minitest/autorun"
require "xcrypt"

class TestXCrypt < Minitest::Test
  # ---------------------------------------------------------------------------
  # algorithms
  # ---------------------------------------------------------------------------

  def test_algorithms_returns_array_of_symbols
    assert_instance_of Array, XCrypt.algorithms
    assert XCrypt.algorithms.all? { |a| a.is_a?(Symbol) }
  end

  def test_algorithms_includes_expected_entries
    %i[yescrypt bcrypt sha512 sha256 md5 des].each do |alg|
      assert_includes XCrypt.algorithms, alg
    end
  end

  # ---------------------------------------------------------------------------
  # detect_algorithm
  # ---------------------------------------------------------------------------

  def test_detect_algorithm_yescrypt
    assert_equal :yescrypt, XCrypt.detect_algorithm("$y$j9T$...")
  end

  def test_detect_algorithm_bcrypt
    assert_equal :bcrypt, XCrypt.detect_algorithm("$2b$12$abc")
  end

  def test_detect_algorithm_sha512
    assert_equal :sha512, XCrypt.detect_algorithm("$6$rounds=5000$abc")
  end

  def test_detect_algorithm_sha256
    assert_equal :sha256, XCrypt.detect_algorithm("$5$rounds=5000$abc")
  end

  def test_detect_algorithm_md5
    assert_equal :md5, XCrypt.detect_algorithm("$1$abc$")
  end

  def test_detect_algorithm_bsdi_des
    assert_equal :bsdi_des, XCrypt.detect_algorithm("_abc")
  end

  def test_detect_algorithm_des
    assert_equal :des, XCrypt.detect_algorithm("ab")
  end

  def test_detect_algorithm_returns_nil_for_unknown
    assert_nil XCrypt.detect_algorithm("$unknown$foo")
  end

  # ---------------------------------------------------------------------------
  # generate_setting
  # ---------------------------------------------------------------------------

  def test_generate_setting_default_returns_string
    setting = XCrypt.generate_setting
    assert_instance_of String, setting
    refute_empty setting
  end

  def test_generate_setting_sha512
    setting = XCrypt.generate_setting(:sha512)
    assert setting.start_with?("$6$"), "expected SHA-512 prefix, got: #{setting}"
  end

  def test_generate_setting_sha256
    setting = XCrypt.generate_setting(:sha256)
    assert setting.start_with?("$5$"), "expected SHA-256 prefix, got: #{setting}"
  end

  def test_generate_setting_bcrypt
    setting = XCrypt.generate_setting(:bcrypt)
    assert setting.start_with?("$2b$"), "expected bcrypt prefix, got: #{setting}"
  end

  def test_generate_setting_md5
    setting = XCrypt.generate_setting(:md5)
    assert setting.start_with?("$1$"), "expected MD5 prefix, got: #{setting}"
  end

  def test_generate_setting_produces_unique_salts
    s1 = XCrypt.generate_setting(:sha512)
    s2 = XCrypt.generate_setting(:sha512)
    refute_equal s1, s2
  end

  def test_generate_setting_raises_for_unknown_algorithm
    assert_raises(ArgumentError) { XCrypt.generate_setting(:nonexistent) }
  end

  # ---------------------------------------------------------------------------
  # crypt
  # ---------------------------------------------------------------------------

  def test_crypt_with_explicit_setting_returns_string
    setting = XCrypt.generate_setting(:sha512)
    hash = XCrypt.crypt("password", setting)
    assert_instance_of String, hash
    refute_empty hash
  end

  def test_crypt_is_deterministic
    setting = XCrypt.generate_setting(:sha512)
    assert_equal XCrypt.crypt("password", setting), XCrypt.crypt("password", setting)
  end

  def test_crypt_same_password_different_salts_differ
    h1 = XCrypt.crypt("password", XCrypt.generate_setting(:sha512))
    h2 = XCrypt.crypt("password", XCrypt.generate_setting(:sha512))
    refute_equal h1, h2
  end

  def test_crypt_with_algorithm_keyword
    hash = XCrypt.crypt("password", algorithm: :sha512)
    assert hash.start_with?("$6$"), "expected SHA-512 hash, got: #{hash}"
  end

  def test_crypt_with_algorithm_symbol_as_first_arg
    hash = XCrypt.crypt("password", :sha512)
    assert hash.start_with?("$6$"), "expected SHA-512 hash, got: #{hash}"
  end

  def test_crypt_raises_on_invalid_setting
    assert_raises(XCrypt::Error) { XCrypt.crypt("password", "!!!invalid!!!") }
  end

  def test_crypt_sha256
    setting = XCrypt.generate_setting(:sha256)
    hash = XCrypt.crypt("s3cr3t", setting)
    assert hash.start_with?("$5$")
  end

  def test_crypt_bcrypt
    setting = XCrypt.generate_setting(:bcrypt)
    hash = XCrypt.crypt("s3cr3t", setting)
    assert hash.start_with?("$2b$")
  end

  def test_crypt_md5
    setting = XCrypt.generate_setting(:md5)
    hash = XCrypt.crypt("s3cr3t", setting)
    assert hash.start_with?("$1$")
  end

  # ---------------------------------------------------------------------------
  # verify
  # ---------------------------------------------------------------------------

  def test_verify_correct_password_returns_true
    hash = XCrypt.crypt("hunter2", algorithm: :sha512)
    assert XCrypt.verify("hunter2", hash)
  end

  def test_verify_wrong_password_returns_false
    hash = XCrypt.crypt("hunter2", algorithm: :sha512)
    refute XCrypt.verify("wrongpassword", hash)
  end

  def test_verify_nil_hash_returns_false
    refute XCrypt.verify("password", nil)
  end

  def test_verify_empty_hash_returns_false
    refute XCrypt.verify("password", "")
  end

  def test_verify_error_string_hash_returns_false
    refute XCrypt.verify("password", "*0")
    refute XCrypt.verify("password", "*")
  end

  def test_verify_invalid_hash_returns_false
    refute XCrypt.verify("password", "not_a_valid_hash")
  end

  def test_verify_bcrypt
    hash = XCrypt.crypt("secret", algorithm: :bcrypt)
    assert XCrypt.verify("secret", hash)
    refute XCrypt.verify("wrong", hash)
  end

  def test_verify_sha256
    hash = XCrypt.crypt("my_pass", algorithm: :sha256)
    assert XCrypt.verify("my_pass", hash)
    refute XCrypt.verify("other", hash)
  end

  # ---------------------------------------------------------------------------
  # XCrypt::Error
  # ---------------------------------------------------------------------------

  def test_error_is_standard_error_subclass
    assert XCrypt::Error < StandardError
  end
end
