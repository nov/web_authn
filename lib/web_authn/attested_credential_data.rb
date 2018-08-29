module WebAuthn
  class AttestedCredentialData
    def initialize(aaguid:, credential_id:, public_key:)
      self.aaguid = aaguid
      self.credential_id = credential_id
      self.public_key = public_key
    end

    class << self
      def decode(attested_credential_data)
        length = (
          ((attested_credential_data.getbyte(16) << 8) & 0xFF) +
          (attested_credential_data.getbyte(17) & 0xFF)
        )
        aaguid,
        credential_id,
        _encoded_cose_key_ = [
          attested_credential_data.byteslice(0...16),
          attested_credential_data.byteslice(18...(18 + length)),
          attested_credential_data.byteslice((18 + length)..-1),
        ]
        cose_key = COSE::Key::EC2.from_cbor(_encoded_cose_key_)
        jwk = JSON::JWK.new(
          kty: :EC,
          crv: :'P-256',
          x: Base64.urlsafe_encode64(cose_key[-2], padding: false),
          y: Base64.urlsafe_encode64(cose_key[-3], padding: false),
        )
        new(
          aaguid: Base64.urlsafe_encode64(aaguid, padding: false),
          credential_id: Base64.urlsafe_encode64(credential_id, padding: false),
          public_key: jwk.to_key
        )
      end
    end
  end
end
