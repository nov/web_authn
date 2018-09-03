# Common
context = WebAuthn.context_for(
  client_data_json,
  origin: request.base_url,
  challenge: session[:challenge],
)

# Registration
raise unless context.registration?

context.verify!(params[:attestation_object])
current_account.fido_authenticators.create(
  credential_id: context.credential_id,
  public_key: context.public_key.to_pem,
  sign_count: context.sign_count
)

# Authentication
raise unless context.authentication?

fido_authentiator = FIDO::Authenticatior.find_by(credential_id: params[:credential_id])
raise unless fido_authentiator.present?

context.verify!(
  authenticator_data,
  public_key: fido_authentiator.public_key,
  sign_count: fido_authentiator.sign_count,
  signature: params[:signature]
)

fido_authentiator.update!(
  sign_count: context.sign_count
)
authenticate authenticator.user
