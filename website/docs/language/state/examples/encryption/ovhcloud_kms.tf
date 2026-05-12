terraform {
  encryption {
    key_provider "ovhcloud_kms" "basic" {
      # Required. KMS endpoint URL.
      # You can also set this using the TF_OKMS_ENDPOINT environment variable.
      endpoint = "https://eu-west-rbx.okms.ovh.net"

      # Required. UUID of the service key used to encrypt/decrypt the data key.
      # You can also set this using the TF_OKMS_KEY_ID environment variable.
      key_id = "00000000-0000-0000-0000-000000000000"

      # Required. Path to the mTLS client certificate.
      # You can also set this using the TF_OKMS_CERT environment variable.
      cert = "/path/to/domain/cert.pem"

      # Required. Path to the mTLS client key.
      # You can also set this using the TF_OKMS_KEY environment variable.
      key = "/path/to/domain/key.pem"

      # Optional. Path to the CA certificate. Default: System CA pool
      # You can also set this using the TF_OKMS_CA environment variable.
      ca = "/path/to/public-ca.crt"

      # Optional. Size of the generated data key in bits.
      # Must be 128, 192 or 256. Default: 256
      key_bits = 256

      # Optional. Name for the generated data key.
      key_name = "my-tofu-data-key"
    }
  }
}
