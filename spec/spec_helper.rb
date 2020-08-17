# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path(__dir__)
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)

require 'omniauth-osso'

require 'omniauth'
require 'omniauth-oauth2'
require 'rack/test'
require 'rspec'
require 'webmock/rspec'

ENV['RACK_ENV'] = 'test'
ENV['SESSION_SECRET'] = 'supersecret'

module RSpecMixin
  include Rack::Test::Methods

  def app
    Rack::Builder.new do
      use OmniAuth::Test::PhonySession
      use OmniAuth::Builder do
        provider :osso, 'abc', 'def', client_options: { site: 'https://api.example.org' }, name: 'example.org'
      end
      run ->(env) { [404, { 'Content-Type' => 'text/plain' }, [env.key?('omniauth.auth').to_s]] }
    end.to_app
  end

  def session
    last_request.env['rack.session']
  end

  def last_json_response
    JSON.parse(last_response.body, symbolize_names: true)
  end
end

RSpec.configure do |config|
  config.include RSpecMixin
  WebMock.disable_net_connect!(allow_localhost: true)
end
