module WebAuthn
  class Context
    class Registration < Context
      attr_accessor :attestation_object

      # TODO: will need more methods, or let developers access deep methods by themselves.
      %i(credential_id rp_id_hash flags public_key public_cose_key sign_count).each do |method|
        delegate method, to: :attestation_object
      end

      def registration?
        true
      end

      def verify!(encoded_attestation_object)
        self.attestation_object = AttestationObject.decode(
          encoded_attestation_object
        )
        verify_flags!
        self
      end

      private

      def verify_flags!
        super
        raise InvalidAssertion, 'Missing Flag: "at"' unless flags.at?
      end
    end
  end
end
