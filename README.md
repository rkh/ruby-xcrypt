# xcrypt

Ruby FFI bindings for [libxcrypt](https://github.com/besser82/libxcrypt), a modern library for one-way password hashing. Supports yescrypt, bcrypt, SHA-512, SHA-256, and other algorithms. The library is bundled as a submodule and compiled statically into the extension, so no system installation of libxcrypt is required.

## Installation

Add this line to your Gemfile:

```ruby
gem "xcrypt"
```

Then run:

```sh
bundle install
```

## Usage

### Hashing a password

Call `XCrypt.crypt` with a passphrase and an algorithm. The library picks a fresh random salt automatically.

```ruby
hash = XCrypt.yescrypt("hunter2")
# => "$y$j9T$..."
```

### Verifying a password

```ruby
XCrypt.verify("hunter2", hash)  # => true
XCrypt.verify("wrong",   hash)  # => false
```

`verify` returns `false` for `nil`, empty strings, and strings starting with `*` (libxcrypt error markers). It never raises.

### Generating a setting string manually

A setting string encodes the algorithm prefix and salt. You can generate one yourself and pass it to `crypt` directly:

```ruby
setting = XCrypt.generate_setting(:bcrypt)
hash    = XCrypt.crypt("hunter2", setting)
```

Passing an explicit setting is useful when you need to control the cost factor:

```ruby
setting = XCrypt.generate_setting(:sha512, cost: 10_000)
hash    = XCrypt.crypt("hunter2", setting)
```

Note that you should always generate a new setting for each password, as it contains a random salt. Reusing the same setting for multiple passwords is not recommended.

As a shorthand, you can also pass the keyword arguments directly to `crypt`:

```ruby
hash = XCrypt.crypt("hunter2", algorithm: :bcrypt, cost: 12)
```

Or to the per-algorithm methods:

```ruby
hash = XCrypt.scrypt("hunter2", n: 2**12, r: 8, p: 1)
```

### Detecting the algorithm of a stored hash

```ruby
XCrypt.detect_algorithm("$6$rounds=5000$abc$...")  # => :sha512
XCrypt.detect_algorithm("$2b$12$...")              # => :bcrypt
```

### Listing supported algorithms

```ruby
XCrypt.algorithms
# => [:yescrypt, :gost_yescrypt, :scrypt, :bcrypt, :sha512, :sha256, :sha1, :sun_md5, :md5, :bsdi_des, :des]
```

## Algorithms

| Symbol          | Prefix   | Notes                                      |
|-----------------|----------|--------------------------------------------|
| `:yescrypt`     | `$y$`    | Recommended for new deployments            |
| `:gost_yescrypt`| `$gy$`   | yescrypt with GOST hash                    |
| `:scrypt`       | `$7$`    | Memory-hard                                |
| `:bcrypt`       | `$2b$`   | Widely deployed, 72-byte passphrase limit  |
| `:sha512`       | `$6$`    |                                            |
| `:sha256`       | `$5$`    |                                            |
| `:sha1`         | `$sha1$` | Legacy                                     |
| `:sun_md5`      | `$md5`   | Legacy                                     |
| `:md5`          | `$1$`    | Legacy                                     |
| `:bsdi_des`     | `_`      | Legacy                                     |
| `:des`          | (none)   | Legacy, 8-character passphrase limit       |

For new deployments, use `:yescrypt` or `:bcrypt`. The legacy algorithms are provided for verifying existing hashes only.

## Error handling

`XCrypt.crypt` and `XCrypt.generate_setting` raise `XCrypt::Error` on failure (invalid setting, unsupported algorithm, bad cost value). `XCrypt.verify` catches these internally and returns `false` instead.

```ruby
XCrypt.crypt("password", "!!!invalid!!!")
# => raises XCrypt::Error

XCrypt.generate_setting(:nonexistent)
# => raises ArgumentError
```

## Development

```sh
bundle install
bundle exec rake compile   # build the native extension
bundle exec rake test      # run the test suite
bundle exec rake           # compile + test
```

## License

MIT. See [MIT-LICENSE](MIT-LICENSE).

The bundled libxcrypt library is licensed under LGPL-2.1. See [ext/libxcrypt/COPYING.LIB](ext/libxcrypt/COPYING.LIB).
