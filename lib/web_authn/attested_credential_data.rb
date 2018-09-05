module WebAuthn
  class AttestedCredentialData
    attr_accessor :aaguid, :credential_id, :public_key

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
        curve_name = case cose_key.curve
        when 1
          'prime256v1'
        when 2
          'secp384r1'
        when 3
          'secp521r1'
        else
          raise NotImplementedError, 'Non-supported EC curve'
        end
        ec_key = OpenSSL::PKey::EC.new curve_name
        ec_key.public_key = OpenSSL::PKey::EC::Point.new(
          OpenSSL::PKey::EC::Group.new(curve_name),
          OpenSSL::BN.new([
            '04' +
            cose_key.x_coordinate.unpack('H*').first +
            cose_key.y_coordinate.unpack('H*').first
          ].pack('H*'), 2)
        )
        new(
          aaguid: Base64.urlsafe_encode64(aaguid, padding: false),
          credential_id: Base64.urlsafe_encode64(credential_id, padding: false),
          public_key: ec_key
        )
      end
    end
  end
end
