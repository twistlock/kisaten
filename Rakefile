# frozen_string_literal: true

require 'rake/extensiontask'
require 'rake/testtask'
require 'rubygems/package_task'

$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)
require 'kisaten/version'

Rake::ExtensionTask.new 'kisaten' do |ext|

  # This causes the shared object to be placed in lib/kisaten/kisaten.so
  # TODO: Test this vs multiple different ruby versions
  ext.lib_dir = 'lib/kisaten'
end

spec = Gem::Specification.new 'kisaten' do |spec|
  spec.summary = 'Ruby MRI extension for fuzzing Ruby code with afl-fuzz'
  spec.version = Kisaten::VERSION
  spec.authors = ["Ariel Zelivansky"]
  spec.email = "ariel.zelivans@gmail.com"
  spec.homepage = "https://github.com/zelivans/kisaten"

  spec.license = 'MIT'

  # This tells RubyGems to build an extension upon install
  spec.extensions = %w[ext/kisaten/extconf.rb]

  spec.files = Dir["Rakefile", "{ext,lib}/**/*.{rb,c}", "LICENSE", "README"]
  spec.required_ruby_version = ">= 2.0.0"  
  spec.add_development_dependency "rake-compiler", "~> 0"

end

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.warning = true
  t.options = "--verbose"
end

# Build the gem in pkg/kisaten.*.gem
Gem::PackageTask.new spec do end

task :default => :test
