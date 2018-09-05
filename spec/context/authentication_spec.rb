RSpec.describe WebAuthn::Context::Authentication do
  let(:context_instance) do
    WebAuthn.context_for(
      client_data_json,
      origin: origin,
      challenge: challenge
    )
  end

  describe '#verify!' do
    let(:client_data_json) do
      'eyJjaGFsbGVuZ2UiOiJjbUZ1Wkc5dExYTjBjbWx1WnkxblpXNWxjbUYwWldRdFlua3RjbkF0YzJWeWRtVnkiLCJvcmlnaW4iOiJodHRwczovL3dlYi1hdXRobi5zZWxmLWlzc3VlZC5hcHAiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0'
    end
    let(:origin) { 'https://web-authn.self-issued.app' }
    let(:challenge) { 'cmFuZG9tLXN0cmluZy1nZW5lcmF0ZWQtYnktcnAtc2VydmVy' }
    let(:rp_id_hash) do
      'MsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJU'
    end
    let(:flags) do
      WebAuthn::AuthenticatorData::Flags.new(
        up: true, uv: false, at: false, ex: false
      )
    end
    let(:public_key) do
      OpenSSL::PKey::EC.new <<~PEM
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMpNU/8TjYoyN8FlhZ+YsOMAvyfQ4
      i6/JN0/DPXuZMoxLvdb1vjh7vPUt2Osw3Bq+0NZsx3U/8kmpFuwsZhTi9A==
      -----END PUBLIC KEY-----
      PEM
    end
    let(:sign_count) { 74 }
    let(:signature) do
      'MEYCIQDmAVQcoMNRJiQZe9o5jJMnYvzza3nkDpnWdmdgKYBfwAIhAINDcFyIpIB8fql4QkllVXrQOkICfi595Gkn313gYG2r'
    end
    let(:authenticator_data) do
      'MsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJUBAAAASg'
    end
    subject do
      context_instance.verify!(
        authenticator_data,
        public_key: public_key,
        sign_count: sign_count - 1,
        signature: signature
      )
    end

    its(:rp_id_hash) { should == rp_id_hash }
    its(:flags) { should == flags }
    its(:sign_count) { should == sign_count }

    context 'when sign count is invalid' do
      let(:sign_count) { 75 }
      it do
        expect do
          subject
        end.to raise_error WebAuthn::InvalidAssertion, 'Invalid Sign Count'
      end
    end

    context 'when signature is invalid' do
      let(:signature) do
        'MEQCIB09d1yFCLxDUJdYIW3HwrZPsNqA1jwLqv_EqyN-xFpYAiAZ5h3RvpxCKvcbwQhqFdw2Chw5rmVD6aAZBNC9tJNmZw'
      end
      it do
        expect do
          subject
        end.to raise_error WebAuthn::InvalidAssertion, 'Invalid Signature'
      end
    end
  end
end
