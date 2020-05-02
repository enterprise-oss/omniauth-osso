# frozen_string_literal: true

require 'omniauth-oauth2'

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
      option :authorize_options, %i[state]
      option :token_params, {}
      option :token_options, []
      option :auth_token_params, {}
      option :provider_ignores_state, false

      def request_phase
        redirect(
          client
            .auth_code
            .authorize_url(
              {
                redirect_uri: callback_url,
                domain: request_domain
              }.merge(authorize_params)
            )
        )
      end

      def authorize_params
        params = options.authorize_params.merge(options_for('authorize')) || {}

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

      def callback_url
        ENV['OSSO_REDIRECT_URI'] || super
      end

      def request_domain
        return @request_domain if defined?(@request_domain)

        @request_domain = request.params['domain'] || request.params['email'].split('@')[1]

        raise StandardError if @request_domain.nil?

        @request_domain
      end
    end
  end
end
