# NOTE:
#  get input data below from this link.
#  https://web-authn.self-issued.app

require 'web_authn'

authenticator_data = 'MsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJUBAAAASg'

signature = 'MEYCIQDmAVQcoMNRJiQZe9o5jJMnYvzza3nkDpnWdmdgKYBfwAIhAINDcFyIpIB8fql4QkllVXrQOkICfi595Gkn313gYG2r'
sign_count = 73

client_data_json = 'eyJjaGFsbGVuZ2UiOiJjbUZ1Wkc5dExYTjBjbWx1WnkxblpXNWxjbUYwWldRdFlua3RjbkF0YzJWeWRtVnkiLCJvcmlnaW4iOiJodHRwczovL3dlYi1hdXRobi5zZWxmLWlzc3VlZC5hcHAiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0'

origin = 'https://web-authn.self-issued.app'
challenge = 'random-string-generated-by-rp-server'

public_key = OpenSSL::PKey::EC.new <<-PEM
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMpNU/8TjYoyN8FlhZ+YsOMAvyfQ4
i6/JN0/DPXuZMoxLvdb1vjh7vPUt2Osw3Bq+0NZsx3U/8kmpFuwsZhTi9A==
-----END PUBLIC KEY-----
PEM

context = WebAuthn.context_for(
  client_data_json,
  origin: origin,
  challenge: challenge,
)
raise unless context.authentication?

context.verify!(
  authenticator_data,
  public_key: public_key,
  sign_count: sign_count,
  signature: signature
)

puts <<-OUT
# RP ID Hash
#{context.rp_id_hash}

# Flags
up: #{context.flags.up}
uv: #{context.flags.uv}
at: #{context.flags.at}
ex: #{context.flags.ex}

# Sign Count
#{context.sign_count}
OUT
