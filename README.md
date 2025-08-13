# IDAuth

Session manager for single page application.

Customizable interfaces for session storage, configuration storage and authentication providers.
Provides default implementations if not provided:

- In-memory or Redis session storage with Azugo cache implementation
- File based client an provider configuration storage

idauth.go contains the main package and the default implementations.
app package contains the runnable application to use out of the box.

Supported authentication providers:

- VPM through wsfed protocol
- OpenID Connect (e.g. Azure AD, Google)

For a more in-depth guide on how to set up IDAuth with other providers, like Google or Azure AD, see the [PROVIDERS.md](PROVIDERS.md) file.

## Run out-of-the-box with Docker

1. Create config files for idauth clients and authentication providers. You can use the provided examples in .config directory.

    ```bash
    cp .config/clients.yaml.example .config/clients.yaml
    cp .config/providers.yaml.example .config/providers.yaml
    ```

1. Run the application with Docker

    ```bash
    docker run -p 8080:8080 -v ${pwd}/.config:/.config github.com/nobid-lsp-latvia/lx-idauth:develop
    ```

## Use as library

If you need to have custom logic for session storage, configuration storage or authentication provider, you can use the library as a dependency.

```go
import "github.com/nobid-lsp-latvia/lx-idauth"

func main() {
    // Create a new IDAuth instance
    auth := idauth.New(app, config.IDAuth).
        WithClientStore(clientStore).
        WithAuthProviderStore(authProviderStore).
        WithCorrelationStore(corelationStore).
        WithOOTStore(ootStore).
        WithSessionStore(sessionStore).
        WithAuthorizer(restApiAuthorizer)

    a := &App{
        App:    app,
        auth:   auth,
        config: config,
    }
}

```

## Docker stack example

```yaml
version: '3.7'
services:
  idauth:
    image: github.com/nobid-lsp-latvia/lx-idauth:develop
    environment:
      AUTH_PROVIDER_STORE_FILE: ".config/providers.yaml"
      AUTHORIZER_REST_API_KEY_FILE: "idauth_authorizer_api_key"
      AUTHORIZER_REST_API_URL: "http://localhost:30001"
      CLIENT_STORE_FILE: ".config/clients.yaml"
      CORS_ORIGINS: "https://localhost:44342"
      ENVIRONMENT: "development"
      SERVER_URLS: "http://localhost:8080"
      SESSION_COUNTDOWN: "5m"
      SESSION_TIMEOUT: "60m"
    configs:
    - source: idauth_clients
      target: .config/clients.yml
    - source: idauth_providers
      target: .config/providers.yml
    - source: idauth_authorizer_api_key
      target: idauth_authorizer_api_key           
configs:
  idauth_clients:
    external: true
  idauth_providers:
    external: true
  idauth_authorizer_api_key:
    external: true
```

### REST API Authorizer

REST API Authorizer is a service that provides user lookup after authentication. It is used to authorize the user based on the token provided by the authentication provider.

The authorizer should have the following endpoints:

POST /authorize

```JSON
{
  "code": "01020311111",
  "first_name": "John",
  "last_name": "Doe"
}
```

Response

```JSON
{
  "user_id": 0,
  "person_code": "string",
  "first_name": "string",
  "last_name": "string",
  "roles": [
    {
      "role_id": 0,
      "role_code": "string",
      "role_name": "string",
      "role_description": "string"
    }
  ]
}
```

Service returning status 422 will be considered as user not registered in the system.
