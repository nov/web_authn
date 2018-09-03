module WebAuthn
  class Context
    class Authentication < Context
      attr_accessor :authenticator_data

      # TODO: will need more methods, or let developers access deep methods by themselves.
      %i(rp_id_hash flags sign_count).each do |method|
        delegate method, to: :authenticator_data
      end

      def authentication?
        true
      end

      def verify!(encoded_authenticator_data, public_key:, sign_count:, signature:)
        raw_authenticator_data = Base64.urlsafe_decode64 encoded_authenticator_data
        self.authenticator_data = AuthenticatorData.decode(
          raw_authenticator_data
        )
        verify_sign_count!(sign_count, authenticator_data.sign_count)
        verify_signature!(raw_authenticator_data, client_data_json.raw, public_key, signature)
        self
      end

      private

      def verify_sign_count!(before, current)
        if before == 0 && current == 0
          self # NOTE: no counter supported on the authenticator
        elsif before < current
          self
        else
          raise 'Invalid Sign Count'
        end
      end

      def verify_signature!(raw_authenticator_data, raw_client_data_json, public_key, signature)
        signature_base_string = [
          raw_authenticator_data,
          OpenSSL::Digest::SHA256.digest(raw_client_data_json)
        ].join
        result = public_key.dsa_verify_asn1(
          OpenSSL::Digest::SHA256.digest(signature_base_string),
          Base64.urlsafe_decode64(signature)
        )
        if result
          self
        else
          raise 'Invalid Signature'
        end
      end
    end
  end
end
