# frozen_string_literal: true

require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    # The main source for the Osso Omniauth Strategy
    class Osso < OmniAuth::Strategies::OAuth2
      attr_accessor :env

      option :name, 'osso'
      option :client_id, nil
      option :client_secret, nil
      option :authorize_options, %i[state]
      option :provider_ignores_state, false

      def request_phase
        redirect(
          client
            .auth_code
            .authorize_url(
              request_params
              .merge(authorize_params)
            )
        )
      end

      def request_params
        {
          redirect_uri: callback_url,
          domain: request_domain
        }
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

      def callback_phase # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
        error = request.params['error_reason'] || request.params['error']

        if error
          fail!(
            error,
            CallbackError.new(
              request.params['error'], request.params['error_description'] ||
              request.params['error_reason'], request.params['error_uri']
            )
          )
        elsif request.params['state'] != 'IDP_INITIATED' &&
              request.params['state'] != session.delete('omniauth.state')

          fail!(:csrf_detected, CallbackError.new(:csrf_detected, 'CSRF detected'))
        else
          self.access_token = build_access_token
          self.access_token = access_token.refresh! if access_token.expired?
          env['omniauth.auth'] = auth_hash
          call_app!
        end
      rescue ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
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
