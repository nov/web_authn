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
        nonce = Base64.encode64(
          OpenSSL::Digest::SHA256.digest [
            authenticator_data.raw,
            OpenSSL::Digest::SHA256.digest(client_data_json.raw)
          ].join
        ).strip
        response.verify! certs.first.public_key
        unless response[:nonce] == nonce
          raise InvalidAttestation, 'Invalid Android Safetynet Response Nonce'
        end
      rescue JSON::JWS::VerificationFailed => e
        raise InvalidAttestation, 'Invalid Android Safetynet Response Signature'
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
