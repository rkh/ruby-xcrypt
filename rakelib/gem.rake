# frozen_string_literal: true

CLOBBER.include("pkg/")
directory "pkg"

namespace :gem do
  desc "Build the source gem (compiles on install)"
  task source: "pkg" do
    require_relative "../lib/xcrypt/version"
    gem_file = "xcrypt-#{XCrypt::VERSION}.gem"
    sh "gem build xcrypt.gemspec"
    FileUtils.mv(gem_file, "pkg/#{gem_file}")
  end

  XCryptBuild::PLATFORMS.each do |platform_key, cfg|
    desc "Build precompiled gem for #{platform_key}"
    task "native:#{platform_key}" => ["pkg", "compile:#{platform_key}"] do
      require_relative "../lib/xcrypt/version"
      gem_file     = "xcrypt-#{XCrypt::VERSION}-#{platform_key}.gem"
      gemspec_file = "_native_#{platform_key.tr("-", "_")}.gemspec"
      File.write(gemspec_file, XCryptBuild.platform_gemspec_content(platform_key, cfg[:ffi_arch_os]))
      begin
        sh "gem build #{gemspec_file}"
        FileUtils.mv(gem_file, "pkg/#{gem_file}")
      ensure
        File.delete(gemspec_file) if File.exist?(gemspec_file)
      end
    end
  end

  desc "Build precompiled gems for all platforms"
  task :native do
    if FFI::Platform.mac?
      XCryptBuild::DARWIN_PLATFORMS.each_key { |p| Rake::Task["gem:native:#{p}"].invoke }
    else
      warn "Skipping macOS platform gems — must be built on macOS"
    end

    require "rake_compiler_dock"
    XCryptBuild::LINUX_PLATFORMS.each_key do |platform_key|
      RakeCompilerDock.sh(
        "BUNDLE_PATH=vendor/bundle bundle install && " \
        "BUNDLE_PATH=vendor/bundle bundle exec rake compile:#{platform_key} gem:native:#{platform_key}",
        platform: platform_key
      )
    end
  end

  desc "Build all gems (source and native)"
  task build: %i[ source native ]

  desc "Publish all built gems to RubyGems.org (requires authentication)"
  task publish: %i[ clobber build test test:linux ] do
    Dir.glob("pkg/*.gem") { sh "gem push #{it}" }
  end
end
