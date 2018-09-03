require 'web_authn'

attestation_object = 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEMsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJVBAAAAMAAAAAAAAAAAAAAAAAAAAAAAQM1zXqvmYeVH9o2q1YcBZDSlkhvVs_2RjnKESVUktkQwQnYcU8jdo-duNLKrIOZNg0g4RCm0UMDZxtdXhR2bCu2lAQIDJiABIVggDMGhDLXoZit2uSMLyL-_emlFrGzlH7b2KpKpgYNzPRYiWCAl795OxcS2QimEnC9Jl_pNG3Gy_9O6m3_GbZdGsk90aw'

client_data_json = 'eyJjaGFsbGVuZ2UiOiJjbUZ1Wkc5dExYTjBjbWx1WnkxblpXNWxjbUYwWldRdFlua3RjbkF0YzJWeWRtVnkiLCJuZXdfa2V5c19tYXlfYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViLWF1dGhuLnNlbGYtaXNzdWVkLmFwcCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ'

origin = 'https://web-authn.self-issued.app'
challenge = 'cmFuZG9tLXN0cmluZy1nZW5lcmF0ZWQtYnktcnAtc2VydmVy'

context = WebAuthn.context_for(
  client_data_json,
  origin: origin,
  challenge: challenge
)
raise unless context.registration?

context.verify! attestation_object

puts <<-OUT
# RP ID Hash
#{context.rp_id_hash}

# Flags
up: #{context.flags.up}
uv: #{context.flags.uv}
at: #{context.flags.at}
ex: #{context.flags.ex}

# Credential ID
#{context.credential_id}

# Public Key
#{context.public_key.to_pem}

# Sign Count
#{context.sign_count}
OUT
