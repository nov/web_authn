Gem::Specification.new do |gem|
  gem.name          = 'web_authn'
  gem.version       = File.read('VERSION')
  gem.authors       = ['nov matake']
  gem.email         = ['nov@matake.jp']
  gem.homepage      = 'https://github.com/nov/web_authn'
  gem.summary       = %q{WebAuthn RP library}
  gem.description   = %q{W3C Web Authentication API (a.k.a. WebAuthN / FIDO 2.0) RP library in Ruby}
  gem.license       = 'MIT'
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.executables   = `git ls-files -- exe/*`.split("\n").map{ |f| File.basename(f) }
  gem.require_paths = ['lib']
  gem.required_ruby_version = '>= 2.3'
  gem.add_runtime_dependency 'activesupport'
  gem.add_runtime_dependency 'cbor'
  gem.add_runtime_dependency 'cose-key', '>= 0.2.0'
  gem.add_runtime_dependency 'json-jwt'
  gem.add_development_dependency 'rake', '~> 10.0'
  gem.add_development_dependency 'simplecov'
  gem.add_development_dependency 'rspec'
  gem.add_development_dependency 'rspec-its'
end
