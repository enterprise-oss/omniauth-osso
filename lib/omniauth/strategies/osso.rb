# frozen_string_literal: true

require 'omniauth-oauth2'
require 'pry'

module OmniAuth
  module Strategies
    # The main source for the Osso Omniauth Strategy
    class Osso < OmniAuth::Strategies::OAuth2
      include OmniAuth::Strategy

      option :name, 'osso'
      option :client_id, nil
      option :client_secret, nil
      option :client_options, { site: ENV['OSSO_BASE_URL'] }
      option :authorize_params, { state: SecureRandom.hex(24) }
      option :authorize_options, %i[state domain]
      option :token_params, {}
      option :token_options, []
      option :auth_token_params, {}
      option :provider_ignores_state, false

      def authorize_params
        params = options.authorize_params.merge(options_for('authorize')) || {}

        raise StandardError if params[:domain].nil?

        if OmniAuth.config.test_mode
          @env ||= {}
          @env['rack.session'] ||= {}
        end

        session['omniauth.state'] = params[:state]

        params
      end

      uid { raw_info['id'] }

      info do
        {
          email: raw_info['email']
        }
      end

      extra do
        {
          idp: raw_info['idp']
        }
      end

      def raw_info
        @raw_info ||= access_token.get("/oauth/me?access_token=#{access_token.token}").parsed
      end

      protected

      def options_for(option)
        options_for = options.send(:"#{option}_options")
        params_for = options.send(:"#{option}_params")

        options_for.each_with_object({}) do |key, hash|
          value = params_for[key] || options[key]
          hash[key.to_sym] = value.respond_to?(:call) ? value.call : value
        end
      end
    end
  end
end
