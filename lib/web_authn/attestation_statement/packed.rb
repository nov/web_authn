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
        verify_certificate! unless self_issued?
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

        if self_issued?
          public_cose_key = authenticator_data.attested_credential_data.public_cose_key
          unless alg == public_cose_key.alg
            raise InvalidAttestation, 'Invalid Packed Self Attestation: alg'
          end
          unless public_cose_key.verify sig, signature_base_string
            raise InvalidAttestation, 'Invalid Packed Self Attestation: signature'
          end
        else
          attestation_certificate = OpenSSL::X509::Certificate.new x5c.first
          public_key = attestation_certificate.public_key
          digest = case public_key
          when OpenSSL::PKey::EC
            COSE::Key::EC2
          when OpenSSL::PKey::RSA
            COSE::Key::RSA
          end.new.tap do |k|
            k.alg = alg
          end.digest
          unless public_key.verify digest, sig, signature_base_string
            raise InvalidAttestation, 'Invalid Packed Attestation: signature'
          end
        end
      end

      def verify_certificate!
        raise NotImplementedError, 'Certificate Chain Verification Not Implemented Yet: packed'
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
