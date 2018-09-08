module WebAuthn
  class AttestedCredentialData
    attr_accessor :aaguid, :credential_id, :public_key, :public_cose_key

    def initialize(aaguid:, credential_id:, public_key:, public_cose_key:)
      self.aaguid = aaguid
      self.credential_id = credential_id
      self.public_key = public_key
      self.public_cose_key = public_cose_key
    end

    class << self
      def decode(attested_credential_data)
        length = (
          ((attested_credential_data.getbyte(16) << 8) & 0xFF) +
          (attested_credential_data.getbyte(17) & 0xFF)
        )
        aaguid,
        credential_id,
        cose_key_cbor = [
          attested_credential_data.byteslice(0...16),
          attested_credential_data.byteslice(18...(18 + length)),
          attested_credential_data.byteslice((18 + length)..-1),
        ]
        cose_key = COSE::Key.decode(cose_key_cbor)
        new(
          aaguid: Base64.urlsafe_encode64(aaguid, padding: false),
          credential_id: Base64.urlsafe_encode64(credential_id, padding: false),
          public_key: cose_key.to_key,
          public_cose_key: cose_key
        )
      end
    end
  end
end
