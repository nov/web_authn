module WebAuthn
  class AttestationStatement
    class AndroidSafetynet < AttestationStatement
      attr_accessor :ver, :response, :certs

      def initialize(ver:, response:)
        self.ver = ver
        self.response = response
        self.certs = response.x5c.collect do |x5c|
          OpenSSL::X509::Certificate.new(
            Base64.decode64 x5c
          )
        end
      end

      def verify!(authenticator_data, client_data_json)
        verify_nonce! authenticator_data, client_data_json
        verify_signature!
        verify_certificate!

        # TODO: put more ref.) https://www.w3.org/TR/webauthn/#android-safetynet-attestation
        unless response[:ctsProfileMatch]
          raise InvalidAttestation, 'Invalid Android Safetynet Response: ctsProfileMatch'
        end
      end

      private

      def verify_nonce!(authenticator_data, client_data_json)
        nonce = Base64.encode64(
          OpenSSL::Digest::SHA256.digest [
            authenticator_data.raw,
            OpenSSL::Digest::SHA256.digest(client_data_json.raw)
          ].join
        ).strip
        unless response[:nonce] == nonce
          raise InvalidAttestation, 'Invalid Android Safetynet Response: nonce'
        end
      end

      def verify_signature!
        response.verify! certs.first.public_key
      rescue JSON::JWS::VerificationFailed => e
        raise InvalidAttestation, 'Invalid Android Safetynet Response: signature'
      end

      def verify_certificate!
        signing_cert = certs.first
        remaining_chain = certs[1..-1]

        store = OpenSSL::X509::Store.new
        store.set_default_paths
        valid_chain = store.verify(signing_cert, remaining_chain)

        valid_subject = signing_cert.subject.to_a.detect do |key, value, type|
          key == 'CN'
        end.second == 'attest.android.com'

        valid_timestamp = (
          signing_cert.not_after > Time.now &&
          signing_cert.not_before < Time.now
        )

        # TODO: do we need CRL check?

        unless valid_chain && valid_subject && valid_timestamp
           raise InvalidAttestation, 'Invalid Android Safetynet Response: certificate chain'
        end
      end

      class << self
        def decode(att_stmt)
          new(
            ver: att_stmt[:ver],
            response: JSON::JWT.decode(att_stmt[:response], :skip_verification)
          )
        end
      end
    end
  end
end
