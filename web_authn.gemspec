Gem::Specification.new do |gem|
  gem.name          = 'web_authn'
  gem.version     = File.read('VERSION')
  gem.authors     = ['nov matake']
  gem.email       = ['nov@matake.jp']
  gem.homepage    = 'https://github.com/nov/web_authn'
  gem.summary     = %q{W3C WebAuthn (a.k.a. FIDO2) RP library in Ruby}
  gem.description = %q{W3C WebAuthn (a.k.a. FIDO2) RP library in Ruby}
  gem.license     = 'MIT'
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.require_paths = ['lib']
  gem.required_ruby_version = '>= 2.3'
  gem.add_runtime_dependency 'json-jwt', '>= 1.9.4'
  gem.add_runtime_dependency 'cbor', '>= 0.5.9.3'
  gem.add_development_dependency 'rake', '~> 10.0'
  gem.add_development_dependency 'simplecov'
  gem.add_development_dependency 'rspec'
  gem.add_development_dependency 'rspec-its'
end
