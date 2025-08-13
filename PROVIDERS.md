# Setting up OIDC Providers

IDAuth supports any OIDC provider that implements the OIDC specification, for example, Azure AD, Google, etc. To set up an OIDC provider, you need to create a new entry in the `providers.yaml` file. Setup on the provider side may differ slightly but in general you need to create a new application and set up the redirect URI to the IDAuth application.

All the providers must be configured to callback to the appropriate IDAuth callback URL, which is `https://idauth:port/idauth/callback/provider_id`, where `provider_id` is the `id` field in the `providers.yaml` file.

For example, for the provider with ID `example` the callback URL would be `https://idauth:port/idauth/callback/example`.

## Setting up Google OAuth2

To set up a authentication provider for Google OAuth2, you need to create a new project in the Google Cloud Console or use an existing project, there are many guides online for this, for example, [this one](https://developers.google.com/identity/protocols/oauth2).

- Under **Authorized redirect URIs**, specify IDAuth's callback for Google, eg. <https://idauth:port/idauth/callback/google>.

Once created, you should recieve a `client_id` and `client_secret` which you can use to create a new entry in the `providers.yaml` file.

```yaml
- id: google
  type: OIDC
  client_id: xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com
  client_secret: xxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxx
  metadata_url: https://accounts.google.com
  scope:
    - openid
    - email
    - profile
```

If not yet done, alter the clients.yaml file to include a client which will allow IDAuth to allow redirection back to this frontend application's auth-done endpoint.

```yaml
- client_id: example
  redirect_uri: 
    - https://frontend:port/auth-done
```

To use this provider, navigate to `https://idauth:port/idauth/authorize?redirect_uri=https://frontend:port/auth-done&auth_type=google&client_id=example`

## Setting up other providers

Azure AD and other OIDC providers can be set up similarly. IDAuth automatically uses the provided `metadata_url` to handle the providers configuration discovery, so you only need to provide the `client_id` and `client_secret`, and configure the redirect URIs on the provider side.
