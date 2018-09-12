module WebAuthn
  class AttestationObject
    attr_accessor :format, :attestation_statement, :authenticator_data
    alias_method :fmt,       :format
    alias_method :att_stmt,  :attestation_statement
    alias_method :auth_data, :authenticator_data

    %i(credential_id rp_id_hash flags public_key public_cose_key sign_count).each do |method|
      delegate method, to: :authenticator_data
    end

    def initialize(fmt:, att_stmt:, auth_data:)
      self.format = fmt
      self.attestation_statement = case format
      when 'none'
        nil
      when 'android-safetynet'
        AttestationStatement::AndroidSafetynet.decode att_stmt
      when 'packed', 'tpm', 'android-key', 'fido-u2f'
        raise NotImplementedError, "Unsupported Attestation Format: #{format}"
      else
        raise InvalidContext, 'Unknown Attestation Format'
      end
      self.authenticator_data = AuthenticatorData.decode auth_data
    end

    def verify_signature!(client_data_json)
      attestation_statement.try(:verify!, authenticator_data, client_data_json)
    end

    class << self
      def decode(encoded_attestation_object)
        cbor = CBOR.decode(
          Base64.urlsafe_decode64 encoded_attestation_object
        ).with_indifferent_access
        new(
          fmt: cbor[:fmt],
          att_stmt: cbor[:attStmt],
          auth_data: cbor[:authData]
        )
      end
    end
  end
end
