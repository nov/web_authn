module WebAuthn
  class AttestationObject
    attr_accessor :format, :attestation_statement, :authenticator_data
    alias_method :fmt,       :format
    alias_method :att_stmt,  :attestation_statement
    alias_method :auth_data, :authenticator_data

    %i(credential_id rp_id_hash flags public_key sign_count).each do |method|
      delegate method, to: :authenticator_data
    end

    def initialize(attrs)
      self.format = attrs[:fmt]
      self.attestation_statement = case format
      when 'none'
        nil
      when 'packed', 'tpm', 'android-key', 'android-safetynet', 'fido-u2f'
        raise "Unsupported Attestation Format: #{attestation_object[:fmt]}"
      else
        raise 'Unknown Attestation Format'
      end
      self.authenticator_data = AuthenticatorData.decode attrs[:authData]
    end

    class << self
      def decode(encoded_attestation_object)
        new CBOR.decode(
          Base64.urlsafe_decode64 encoded_attestation_object
        ).with_indifferent_access
      end
    end
  end
end
