require 'web_authn'

attestation_object = 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEMsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJVBAAAASQAAAAAAAAAAAAAAAAAAAAAAQA3sNJGmV3TJ2Y5pYDZP-DpZIku6rXhmhUZJ5kNNlaI3-4wwfhl296tAl52zStVDUsLVIm4_e4apQWUwl6eGnXalAQIDJiABIVggmQvMomjF0F3asbDWda13XeA1UbXdcS5j3Wg3G1LtgaMiWCBlNRc_WstNxVl56t6fVIJuVjMZqon1GpDp_UDDTXO7_g'

client_data_json = 'eyJjaGFsbGVuZ2UiOiJjbUZ1Wkc5dExYTjBjbWx1WnkxblpXNWxjbUYwWldRdFlua3RjbkF0YzJWeWRtVnkiLCJvcmlnaW4iOiJodHRwczovL3dlYi1hdXRobi5zZWxmLWlzc3VlZC5hcHAiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0'

origin = 'https://web-authn.self-issued.app'
challenge = 'random-string-generated-by-rp-server'

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
