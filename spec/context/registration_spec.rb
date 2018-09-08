RSpec.describe WebAuthn::Context::Registration do
  let(:context) { registration_context }
  let(:context_instance) do
    WebAuthn.context_for(
      client_data_json,
      origin: context[:origin],
      challenge: context[:challenge]
    )
  end

  describe '#verify!' do
    let(:credential_id) do
      'Dew0kaZXdMnZjmlgNk_4OlkiS7qteGaFRknmQ02Vojf7jDB-GXb3q0CXnbNK1UNSwtUibj97hqlBZTCXp4addg'
    end
    let(:rp_id_hash) do
      'MsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJU'
    end
    let(:flags) do
      WebAuthn::AuthenticatorData::Flags.new(
        up: true, uv: false, at: true, ex: false
      )
    end
    let(:public_key_pem) do
      <<~PEM
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmQvMomjF0F3asbDWda13XeA1UbXd
      cS5j3Wg3G1LtgaNlNRc/WstNxVl56t6fVIJuVjMZqon1GpDp/UDDTXO7/g==
      -----END PUBLIC KEY-----
      PEM
    end
    let(:sign_count) { 73 }
    let(:attestation_object) do
      'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEMsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJVBAAAASQAAAAAAAAAAAAAAAAAAAAAAQA3sNJGmV3TJ2Y5pYDZP-DpZIku6rXhmhUZJ5kNNlaI3-4wwfhl296tAl52zStVDUsLVIm4_e4apQWUwl6eGnXalAQIDJiABIVggmQvMomjF0F3asbDWda13XeA1UbXdcS5j3Wg3G1LtgaMiWCBlNRc_WstNxVl56t6fVIJuVjMZqon1GpDp_UDDTXO7_g'
    end
    subject { context_instance.verify! attestation_object }

    its(:credential_id) { should == credential_id }
    its(:rp_id_hash) { should == rp_id_hash }
    its(:flags) { should == flags }
    its(:public_key) { should be_instance_of OpenSSL::PKey::EC }
    its(:public_cose_key) { should be_instance_of COSE::Key::EC2 }
    its(:public_key_pem) do
      subject.public_key.to_pem.should == public_key_pem
    end
    its(:sign_count) { should == sign_count }
  end
end
