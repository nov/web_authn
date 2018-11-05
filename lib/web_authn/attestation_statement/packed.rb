module WebAuthn
  class AttestationStatement
    class Packed < AttestationStatement
      attr_accessor :alg, :sig, :x5c, :ecdaa_key_id

      def initialize(alg:, sig:, x5c:, ecdaa_key_id:)
        self.alg = alg
        self.sig = sig
        self.x5c = Array(x5c)
        self.ecdaa_key_id = ecdaa_key_id
      end

      def verify!(authenticator_data, client_data_json)
        verify_signature! authenticator_data, client_data_json
      end

      private

      def self_issued?
        [x5c, ecdaa_key_id].all?(&:blank?)
      end

      def verify_signature!(authenticator_data, client_data_json)
        signature_base_string = [
          authenticator_data.raw,
          OpenSSL::Digest::SHA256.digest(client_data_json.raw)
        ].join

        if self_issued? && authenticator_data.attested_credential_data.anonymous?
          public_cose_key = authenticator_data.attested_credential_data.public_cose_key
          unless alg == public_cose_key.alg
            raise InvalidAttestation, 'Invalid Packed Self Attestation: alg'
          end
          unless public_cose_key.verify sig, signature_base_string
            raise InvalidAttestation, 'Invalid Packed Self Attestation: signature'
          end
        else
          raise NotImplementedError, "Unsupported Attestation Format: packed"
        end
      end

      class << self
        def decode(att_stmt)
          new(
            alg: att_stmt[:alg],
            sig: att_stmt[:sig],
            x5c: att_stmt[:x5c],
            ecdaa_key_id: att_stmt[:ecdaaKeyId]
          )
        end
      end
    end
  end
end
