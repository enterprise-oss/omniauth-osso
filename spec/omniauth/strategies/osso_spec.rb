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
      instance = subject.new('abc', 'def', authorize_params: { state: 'qux' })
      expect(instance.authorize_params.keys).to include('state')
      expect(instance.session['omniauth.state']).to eq('qux')
    end
  end

  describe '#token_params' do
    subject { fresh_strategy }

    it 'includes any authorize params passed in the :authorize_params option' do
      instance = subject.new('abc', 'def', token_params: { foo: 'bar', baz: 'zip' })
      expect(instance.token_params).to eq('foo' => 'bar', 'baz' => 'zip')
    end

    it 'includes top-level options that are marked as :authorize_options' do
      instance = subject.new('abc', 'def', token_options: %i[scope foo], scope: 'bar', foo: 'baz')
      expect(instance.token_params).to eq('scope' => 'bar', 'foo' => 'baz')
    end
  end

  describe '#callback_phase' do
    subject { fresh_strategy }
    it 'calls fail with the client error received' do
      instance = subject.new('abc', 'def')
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
