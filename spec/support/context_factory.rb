module ContextFactory
  extend RSpec::Core::SharedContext

  let(:base_context) do
    {
      challenge: SecureRandom.hex(8),
      origin: 'https://rp.example.com'
    }
  end
  let(:registration_context) do
    base_context.merge(type: 'webauthn.create')
  end
  let(:authentication_context) do
    base_context.merge(type: 'webauthn.get')
  end
  let(:unknown_context) do
    base_context
  end
  let(:client_data_json) do
    _context_ = context.dup
    _context_[:challenge] = Base64.urlsafe_encode64(_context_[:challenge], padding: false)
    Base64.urlsafe_encode64(_context_.to_json, padding: false)
  end
end

RSpec.configure do |config|
  config.include ContextFactory
end
