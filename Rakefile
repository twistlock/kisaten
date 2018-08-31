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
  spec.summary = 'Ruby instrumentation for afl fuzzing'
  spec.version = Kisaten::VERSION
  spec.authors = ["Ariel Zelivansky"]

  spec.license = 'MIT'

  # This tells RubyGems to build an extension upon install
  spec.extensions = %w[ext/kisaten/extconf.rb]

  spec.files = Dir["Rakefile", "{ext,lib}/**/*.{rb,c}", "LICENSE", "README"]
  spec.required_ruby_version = ">= 2.0.0"  
  spec.add_development_dependency "rake-compiler"

end

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.warning = true
  t.verbose = true
end

# Build the gem in pkg/kisaten.*.gem
Gem::PackageTask.new spec do end

task :default => :test
