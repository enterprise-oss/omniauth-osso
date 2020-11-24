# frozen_string_literal: true

require File.expand_path('lib/omniauth-osso/version', __dir__)

Gem::Specification.new do |gem|
  gem.authors       = ['Sam Bauch']
  gem.email         = ['sbauch@gmail.com']
  gem.description   = 'An OAuth 2.0 OmniAuth provider for Osso SSO.'
  gem.summary       = gem.description
  gem.homepage      = 'https://github.com/enterprise-oss/omniauth-osso'
  gem.license       = 'BSL'

  gem.add_dependency 'omniauth-oauth2', '~> 1.6.0'
  gem.add_development_dependency 'bundler', '~> 2.1'

  gem.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name          = 'omniauth-osso'
  gem.require_paths = ['lib']
  gem.version       = OmniAuth::Osso::VERSION
  gem.required_ruby_version = '~> 2.4'
end
