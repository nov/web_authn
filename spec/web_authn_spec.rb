RSpec.describe WebAuthn do
  shared_examples_for :invalid_context do
    it do
      expect do
        subject
      end.to raise_error WebAuthn::InvalidContext
    end
  end

  shared_examples_for :context_validator do
    context 'when invalid origin' do
      let(:origin) { 'https://other-rp.example.com' }
      it_behaves_like :invalid_context
    end

    context 'when invalid challenge' do
      let(:challenge) { SecureRandom.hex(8) }
      it_behaves_like :invalid_context
    end
  end

  describe '#context_for' do
    let(:origin) { context[:origin] }
    let(:challenge) { context[:challenge] }
    subject do
      described_class.context_for(
        client_data_json,
        origin: origin,
        challenge: challenge,
      )
    end

    context 'when registration context' do
      let(:context) { registration_context }
      it_behaves_like :context_validator
      it { should be_instance_of WebAuthn::Context::Registration }
      it { should be_registration }
      it { should_not be_authentication }
    end

    context 'when authentication context' do
      let(:context) { authentication_context }
      it_behaves_like :context_validator
      it { should be_instance_of WebAuthn::Context::Authentication }
      it { should_not be_registration }
      it { should be_authentication }
    end

    context 'when unknown context' do
      let(:context) { unknown_context }
      it_behaves_like :invalid_context
    end
  end
end
