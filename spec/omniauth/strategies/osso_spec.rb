# frozen_string_literal: true

require 'spec_helper'

describe OmniAuth::Strategies::Osso do
  let(:fresh_strategy) { Class.new(OmniAuth::Strategies::Osso) }

  before do
    OmniAuth.config.test_mode = true
  end

  after do
    OmniAuth.config.test_mode = false
  end

  describe 'Subclassing Behavior' do
    subject { fresh_strategy }

    it 'performs the OmniAuth::Strategy included hook' do
      expect(OmniAuth.strategies).to include(OmniAuth::Strategies::Osso)
      expect(OmniAuth.strategies).to include(subject)
    end
  end

  describe '#client' do
    subject { fresh_strategy }

    it 'is initialized with symbolized client_options' do
      instance = subject.new(app, client_options: { 'authorize_url' => 'https://example.com' })
      expect(instance.client.options[:authorize_url]).to eq('https://example.com')
    end

    it 'sets ssl options as connection options' do
      instance = subject.new(app, client_options: { 'ssl' => { 'ca_path' => 'foo' } })
      expect(instance.client.options[:connection_opts][:ssl]).to eq(ca_path: 'foo')
    end
  end

  describe '#authorize_params' do
    subject { fresh_strategy }

    it 'includes random state in the authorize params' do
      instance = subject.new('abc', 'def')
      expect(instance.authorize_params.keys).to include('state')
      expect(instance.session['omniauth.state']).not_to be_empty
    end

    it 'includes custom state in the authorize params' do
      instance = subject.new('abc', 'def', state: 'qux')
      expect(instance.authorize_params.keys).to include('state')
      expect(instance.session['omniauth.state']).to eq('qux')
    end
  end

  describe '#request_params' do
    let(:url) { 'https://example.com/auth/osso' }
    subject { fresh_strategy }

    before do
      OmniAuth.config.full_host = 'https://osso-base.com'
    end

    it 'includes domain passed as a request param' do
      instance = subject.new('abc', 'def')
      instance.env = {}
      allow(instance).to receive(:request) do
        double('Request', params: { 'domain' => 'example.com' }, scheme: 'https', url: url)
      end

      expect(instance.request_params[:domain]).to eq('example.com')
    end

    it 'includes email passed as a request param' do
      instance = subject.new('abc', 'def')
      instance.env = {}
      allow(instance).to receive(:request) do
        double('Request', params: { 'email' => 'user@example.com' }, scheme: 'https', url: url)
      end

      expect(instance.request_params[:email]).to eq('user@example.com')
    end

    it 'only includes email as a request param when both keys are provided' do
      instance = subject.new('abc', 'def')
      instance.env = {}
      allow(instance).to receive(:request) do
        double('Request', params: { 'email' => 'user@example.com', 'domain' => 'example.com' }, scheme: 'https',
                          url: url)
      end

      expect(instance.request_params[:email]).to eq('user@example.com')
      expect(instance.request_params.keys).to_not include(:domain)
    end

    it 'only includes redirect_uri as a request param if neither email or domain are provided' do
      instance = subject.new('abc', 'def')
      instance.env = {}
      allow(instance).to receive(:request) do
        double('Request', params: {}, scheme: 'https', url: url)
      end

      expect(instance.request_params.keys).to eq([:redirect_uri])
    end
  end

  # We need to get a little hacky with testing the callback phase
  # in order to cover IDP initiated flows. When a user opens
  # an SP app by clicking a tile on their IDP, then the OAuth flow
  # skips the first leg, and we have to ignore CSRF protection.
  # Osso will send `state=IDP_INITIATED_FLOW` when this is the case,
  # and here we ensure that our strategy completes the callback phase
  # with this state param.

  describe '#callback_phase' do
    subject { fresh_strategy }
    let(:url) { 'https://example.com/auth/osso/callback' }
    let(:instance) { subject.new(app, 'abc', 'def') }

    before do
      OmniAuth.config.test_mode = true
      ENV['OSSO_BASE_URL'] = 'https://osso-base.com'
      allow(instance).to receive(:auth_hash) { auth_hash }
      instance.env = {}
    end

    let :auth_hash do
      {
        provider: 'osso',
        uid: 'uuid',
        info: {
          email: 'user@enterprise.com',
          name: 'user@enterprise.com'
        },
        credentials: {
        },
        extra: {
        }
      }
    end

    it 'allows callbacks with IDP_INITIATED state param' do
      allow(instance).to receive(:request) do
        double('Request', params: { 'state' => 'IDP_INITIATED' }, scheme: 'https', url: url)
      end

      allow(instance).to receive(:build_access_token) do
        double('AccessToken', expired?: false, token: 'token')
      end

      expect(instance).to_not receive(:fail!)
      instance.callback_phase
    end

    it 'calls fail with the client error received' do
      allow(instance).to receive(:request) do
        double('Request', params: { 'error_reason' => 'user_denied', 'error' => 'access_denied' })
      end

      expect(instance).to receive(:fail!).with('user_denied', anything)
      instance.callback_phase
    end
  end
end

describe OmniAuth::Strategies::Osso::CallbackError do
  let(:error) { Class.new(OmniAuth::Strategies::Osso::CallbackError) }
  describe '#message' do
    subject { error }
    it 'includes all of the attributes' do
      instance = subject.new('error', 'description', 'uri')
      expect(instance.message).to match(/error/)
      expect(instance.message).to match(/description/)
      expect(instance.message).to match(/uri/)
    end
    it 'includes all of the attributes' do
      instance = subject.new(nil, :symbol)
      expect(instance.message).to eq('symbol')
    end
  end
end
