# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs    << "lib"
  t.pattern = "test/**/test_*.rb"
  t.verbose = true
end

# Linux tests are only meaningful to run from macOS (they go through Docker).
# On a Linux CI host the normal `rake test` already covers the native platform.
if FFI::Platform.is_os("linux")
  task "test:linux" => :test
else
  namespace :test do
    XCryptBuild::LINUX_PLATFORMS.each_key do |platform_key|
      desc "Run tests inside the #{platform_key} Docker image"
      task platform_key do
        require "rake_compiler_dock"
        RakeCompilerDock.sh(
          "BUNDLE_PATH=vendor/bundle bundle install && " \
          "BUNDLE_PATH=vendor/bundle bundle exec rake compile test:linux",
          platform: platform_key
        )
      end
    end

    desc "Run tests on all Linux platforms via Docker"
    task linux: XCryptBuild::LINUX_PLATFORMS.keys.map { |p| "test:#{p}" }
  end
end
