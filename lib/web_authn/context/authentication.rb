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
        self.authenticator_data = AuthenticatorData.decode(
          Base64.urlsafe_decode64 encoded_authenticator_data
        )
        verify_flags!
        verify_sign_count!(sign_count)
        verify_signature!(public_key, signature)
        self
      end

      private

      def verify_flags!
        super
        raise InvalidAssertion, 'Unexpected Flag: "at"' if flags.at?
      end

      def verify_sign_count!(before)
        if before == 0 && sign_count == 0
          self # NOTE: no counter supported on the authenticator
        elsif before < sign_count
          self
        else
          raise InvalidAssertion, 'Invalid Sign Count'
        end
      end

      def verify_signature!(public_key, signature)
        signature_base_string = [
          authenticator_data.raw,
          OpenSSL::Digest::SHA256.digest(client_data_json.raw)
        ].join
        result = public_key.verify(
          OpenSSL::Digest::SHA256.new,
          Base64.urlsafe_decode64(signature),
          signature_base_string
        )
        if result
          self
        else
          raise InvalidAssertion, 'Invalid Signature'
        end
      end
    end
  end
end
