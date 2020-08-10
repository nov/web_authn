module WebAuthn
  class AttestationStatement
    class Apple < AttestationStatement
      CERTIFICATE_EXTENSION_OID = '1.2.840.113635.100.8.2'
      ROOT_CERTIFICATE = <<~PEM
        -----BEGIN CERTIFICATE-----
        MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
        HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
        bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
        NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
        A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
        AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
        xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
        pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
        2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
        MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
        jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
        1bWeT0vT
        -----END CERTIFICATE-----
      PEM

      attr_accessor :alg, :x5c, :certs

      def initialize(alg:, x5c:)
        self.alg = alg
        self.x5c = Array(x5c)
        self.certs = self.x5c.collect do |x5c|
          OpenSSL::X509::Certificate.new x5c
        end
      end

      def verify!(authenticator_data, client_data_json)
        verify_nonce! authenticator_data, client_data_json
        verify_certificate! authenticator_data.attested_credential_data
      end

      private

      def verify_nonce!(authenticator_data, client_data_json)
        nonce = OpenSSL::Digest::SHA256.digest [
          authenticator_data.raw,
          OpenSSL::Digest::SHA256.digest(client_data_json.raw)
        ].join

        extension = certs.first.find_extension(CERTIFICATE_EXTENSION_OID)
        expected_nonce = OpenSSL::ASN1.decode(extension.value_der).first.value.first.value

        unless expected_nonce == nonce
          raise InvalidAttestation, 'Invalid Apple Response: nonce'
        end
      end

      def verify_certificate!(attested_credential_data)
        attested_cert = certs.first
        remaining_chain = certs[1..-1]

        store = OpenSSL::X509::Store.new
        store.add_cert OpenSSL::X509::Certificate.new ROOT_CERTIFICATE
        valid_chain = store.verify(attested_cert, remaining_chain)

        valid_timestamp = (
          attested_cert.not_after > Time.now &&
          attested_cert.not_before < Time.now
        )

        valid_attested_public_key = (
          attested_credential_data.public_key.to_pem ==
          attested_cert.public_key.to_pem
        )

        # TODO: do we need CRL check?

        unless valid_chain && valid_attested_public_key && valid_timestamp
           raise InvalidAttestation, 'Invalid Apple Response: certificate'
        end
      end

      class << self
        def decode(att_stmt)
          new(
            alg: att_stmt[:alg],
            x5c: att_stmt[:x5c]
          )
        end
      end
    end
  end
end
