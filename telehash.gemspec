# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'telehash/version'

Gem::Specification.new do |spec|
  spec.name          = "telehash"
  spec.version       = Telehash::VERSION
  spec.authors       = ["David Waite"]
  spec.email         = ["david@alkaline-solutions.com"]
  spec.summary       = %q{Implementation of the Telehash protocol}
  spec.description   = %q{Implementation of the Telehash protocol. See http://www.telehash.org}
  spec.homepage      = "http://www.telehash.org/"
  spec.license       = "MIT"


  signing_key = Dir.glob(Dir.home + '/.gem/keys/*private*.pem').first
  chain = Dir.glob(Dir.home + '/.gem/keys/*public*.pem')
  if signing_key
    spec.signing_key   = signing_key
    spec.cert_chain    = chain
  end

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler",  ">= 1.3.5"
  spec.add_development_dependency "rake",     ">= 10.1.0"
  spec.add_development_dependency "minitest", ">= 5.0.6"
end
