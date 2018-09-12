module WebAuthn
  class AttestationObject
    attr_accessor :format, :attestation_statement, :authenticator_data
    alias_method :fmt,       :format
    alias_method :att_stmt,  :attestation_statement
    alias_method :auth_data, :authenticator_data

    %i(credential_id rp_id_hash flags public_key public_cose_key sign_count).each do |method|
      delegate method, to: :authenticator_data
    end

    def initialize(fmt:, att_stmt:, auth_data:, ignore_attestation: false)
      self.format = fmt
      self.attestation_statement = case format
      when 'none'
        nil
      when 'packed', 'tpm', 'android-key', 'android-safetynet', 'fido-u2f'
        if ignore_attestation
          Warning.warn '[WARN] Skipping Attestation Verification'
        else
          raise NotImplementedError, "Unsupported Attestation Format: #{format}"
        end
      else
        raise InvalidContext, 'Unknown Attestation Format'
      end
      self.authenticator_data = AuthenticatorData.decode auth_data
    end

    class << self
      def decode(encoded_attestation_object, ignore_attestation: false)
        cbor = CBOR.decode(
          Base64.urlsafe_decode64 encoded_attestation_object
        ).with_indifferent_access
        new(
          fmt: cbor[:fmt],
          att_stmt: cbor[:attStmt],
          auth_data: cbor[:authData],
          ignore_attestation: ignore_attestation
        )
      end
    end
  end
end
