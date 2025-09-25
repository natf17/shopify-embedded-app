# Shopify Embedded App Authorization: Rebuilt for Spring Security 7

This application demonstrates how to tweak Spring Security to authorize a Shopify embedded app.

# Prerequisites
- An environment using Java 24.
- A Shopify development store (you can create one from your [Dev Dashboard](https://dev.shopify.com/dashboard/))
- A Shopify app in the Dev Dashboard that can be used to test this project. You can create one from your [Dev Dashboard](https://dev.shopify.com/dashboard/) and accept all the defaults.
  - Make note of scopes you want to add to the app
- Maven

# Running the app
1. Git clone this project.
2. Obtain the following information from your app in the Dev Dashboard:
   - client id -> save it in the env. variable `app_client_id`
   - client secret -> save it in the env. variable `app_client_secret`
3. Save the scopes (comma-delimited list, no spaces) in an env. variable: `app_scopes`
   - You can use `write_products` as a test 
4. Set the profile to `dev` (e.g. set the env. variable: `SPRING_PROFILES_ACTIVE=dev`)
5. cd into the backend module: `cd backend`
5. Start the spring boot app: `mvn spring-boot:run`
6. Create a tunnel to make `localhost:8080` publicly accessible. You can use ngrok.
7. In your Dev Dashboard, click on your app and click `Create a version`.
   - Enter the "App Url": `https://{your-hostname}/app/shopify`
   - Select "Embed app in Shopify admin"
   - Add all the scopes that are in the `application.properties`
   - Under "Redirect URLs", add: `https://{your-hostname}/authorized/shopify`
   - Click `Release`
8. In your Dev Dashboarrd, click on your app and under `Home`, click `Install App` and select your test store.

After granting the permissions requested, you should see a welcome page.

# Endpoints
These are the app endpoints:

`/app/shopify`: the app uri
- to access the embedded app (and install)
- if called by Shopify from an embedded app 
  - and already installed, the request will go through the chain and the SPA will be returned
  - if not installed, we initiate the OAuth flow via a Shopify App Bridge redirect (written directly to the response)
- if not called by Shopify (e.g. when App Bridge redirects to break out of the iframe) it always initiates the OAuth flow.
  - This requires `shop` to be present as a request parameter.

`/authorized/shopify`: the app redirect uri
- called by Shopify during the OAuth flow


# How it works
## The app (SPA)
The following outlines how this project meets the Shopify requirements for app installation as described [here](https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens/authorization-code-grant):
- We customize the Spring Security OAuth2 Client to perform the Authorization code grant flow and obtain the token upon installation:

Scenario 1: The shop is being installed: (`/app/shopify`)
- Step 1: Verify the installation request: See `ShopifyRequestAuthenticationFilter`, `ShopifyRequestAuthenticationToken`
  - Embedded: `ShopifyRequestAuthenticationProvider` authenticates the request, but the principal reflects that no OAuth token was found.
  - Not embedded: the request remains unauthenticated
- Step 2: Request authorization code
  - In `OAuth2AuthorizationRequestRedirectFilter`, `ShopifyOAuth2AuthorizationRequestResolver` builds a `OAuth2AuthorizationRequest` for the redirect. We need the `shop` to build the OAuth uris.
    - Embedded: The `shop` parameter is resolved from the `Authentication`. All other params also resolved here.
    - Not embedded: The `shop` parameter is resolved via a query param. All other params also resolved here.
  - `ShopifyAuthorizationRequestRedirectStrategy` chooses where to redirect to.
    - Embedded: returns a generated html page that will exit the iframe page via an AppBridge redirect to the app uri
    - Not embedded: redirects to the authorization uri
- Step 3: Validate authorization code: `ShopifyOAuth2AuthorizationCodeAuthenticationProvider`
  - Nonce check (nonce sent to authorization uri in query = nonce in current request from Shopify): the nonce sent to the auth server is guaranteed to be the same as the nonce in the cookie. So it is sufficient to only check the cookie.
  - Nonce check (cookie = nonce in the query)
    - `CookieOAuth2AuthorizationRequestRepository` reads the `OAuth2AuthorizationRequest` saved in the cookie, which includes the nonce.
    - `OAuth2AuthorizationCodeAuthenticationProvider` compares with the nonce in current request params
  - HMAC check (already done by `ShopifyRequestAuthenticationFilter`)
  - Check for valid `shop` parameter (see `ShopifyOAuth2AuthorizationCodeAuthenticationProvider`)
- Step 4: Get an access token:
  - insert shop name into token uri (`ShopifyOAuth2AuthorizationCodeAuthenticationProvider`)
  - add parameters to body (already down by default: `RestClientAuthorizationCodeTokenResponseClient` and `DefaultOAuth2TokenRequestParametersConverter`)
  - process response: `access_token` and `scope` values
    - `DefaultMapOAuth2AccessTokenResponseConverter` (used by `RestClientAuthorizationCodeTokenResponseClient` to parse the response) correctly extracts these values.
    - However, it expects to find a token type in the response. We have to add it.
    - However, the `scope` string is split with `" "` as delimiter. We need to use `","`. We also have to it add the token type to the response before passing it to the default impl.
      - see `ShopifyMapOAuth2AccessTokenResponseConverter`
  - Note: if the authorization server responds with an error, `OAuth2AuthorizationCodeGrantFilter` will redirect to the redirect uri with error params. On the second pass, the filter will not match the request as an authorization response and will let the request continue. Further down the filter chain, if this path (redirect uri) requires the user to be authenticated, the AuthorizationFilter will throw an `AccessDeniedException` because the request didn't come from Shopify.
  - The approved scopes are verified in `ShopifyOAuth2AuthorizationCodeAuthenticationProvider`
  - The default `OAuth2AuthorizedClientRepository` implementation (`AuthenticatedPrincipalOAuth2...`) uses our custom `AccessTokenService` to save the token
- Step 5: Redirect to your app's UI: by default, `OAuth2AuthorizationCodeGrantFilter` checks the `RequestCache` for a `SavedRequest` to determine where to redirect to
  - `ShopifyAppRequestCache` always returns a `SavedRequest` with the redirect url:
    - the full app url (`/app/shopify?shop={shop}&host={host}`)
    - or to embedded app url (`"https://{base64_decoded_host}/apps/{api_key}/`)
- See scenario 2. 

- Scenario 2: The shop is already installed, and we have a token (`/app/shopify`)
- Step 1: Verify the installation request: 
  - Embedded:`ShopifyInstallationRequestFilter` authenticates the request
  - Not embedded: the request is left unauthenticated
- `OAuth2AuthorizationRequestRedirectFilter` delegates to `ShopifyOAuth2AuthorizationRequestResolver` which checks the scope of the token found: 
  - if not all scopes granted, it reverts to scenario 1
  - if the scopes match, the OAuth flow is not initiated and the request continues through the chain. 
- Since the request is authenticated, it'll go through the entire chain.

Note: 
- if the app is not embedded, the OAuth authorization flow is entered every time.
- the SPA is returned if and only if there is a valid OAuth token for that shop.

## The API
- **COMING SOON**: Spring Security OAuth2 Resource Server will validate the session token


## The Database
Your database table is expected to have the following schema:
```
|----------------shopify_oauth_access_tokens----------------|
|                                                           |
|----id----shop----access_token----scope----date_created----|
|                                                           |
|-----------------------------------------------------------|
```
An H2 in-memory database is configured to run when running in the `dev` profile. 
If desired, an H2-in-memory database can be configured when running integration tests. The single existing integration test activates the test profile.

# TODOs
- encode the token in DB
-  build up `ShopifyAppRequestCache` so that it is a fully functional cookie-based request cache
- `ShopifyAccessToken` scopes should be a set, not a String. Better yet, replace the custom token with the Spring default
- Offer a way of authenticating non-embedded requests. Currently the only way is via Shopify (embedded). 
- Consolidate the retrieval of the OAuth token in `AccessTokenService` to perhaps only use the `OAuth2AuthorizedClientService` interface
  - (`ShopifyRequestAuthenticationFilter` should use `AccessTokenService`)
- `ShopifyRequestAuthenticationFilter` should only allow authenticated access to the redirect uri