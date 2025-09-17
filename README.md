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
6. Create a tunnel to make `localhost:8081` publicly accessible. You can use ngrok or pinggy.
7. In your Dev Dashboard, create a new version configure it:
   - Enter the "App Url": `https://{your-hostname}/shopify`
   - Select "Embed app in Shopify admin"
   - Add all the scopes that are in the `application.properties`
   - Select "Use legacy install flow"
   - Under "Redirect URLs", add: https://{your-hostname}/authorized/shopify
8. ...

## Adding the project


# The Database

Your database is expected to have the following schema:
```
|---------------------------STOREACCESSTOKENS-------------------------------|
|                                                                           |
|id--storeDomain--tokenType--tokenValue--salt--issuedAt--expiresAt--scopes--|
|                                                                           |
|---------------------------------------------------------------------------|
```

## Url paths
These are the app endpoints:

`/shopify`:
- to access the embedded app (and install)
- must be called by Shopify from an embedded app 
  - and already installed, the request will go through the chain and the SPA will be returned
  - if not installed, spring security initiates the OAuth flow via a 3XX redirect or Shopify App Bridge redirect (written directly to the response)

`/authorized/shopify`:
- called by Shopify during the OAuth flow


# How it works
The following outlines how this project meets the Shopify requirements for app installation as described [here](https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens/authorization-code-grant):
- We leverage Spring Security OAuth2 Client to perform the Authorization code grant flow and obtain the token upon installation:
- Scenario 1: The shop is being installed (`/shopify`)
  - Step 1: Verify the installation request: See `ShopifyRequestAuthenticationFilter`, `ShopifyRequestAuthenticationToken`
  - `ShopifyRequestAuthenticationProvider` authenticates the request, but the principal reflects that no OAuth token was found.
  - In `OAuth2AuthorizationRequestRedirectFilter`, `ShopifyOAuth2AuthorizationRequestResolver` builds a `OAuth2AuthorizationRequest` for the redirect (Step 2: Request authorization code)
  - `ShopifyAuthorizationRequestRedirectStrategy`
    - if embedded: returns a generated html page that will exit the iframe page via an AppBridge redirect
    - if not embedded: redirects to the authorization uri
  - Step 3: Validate authorization code: `ShopifyOAuth2AuthorizationCodeAuthenticationProvider`
    - Nonce check (nonce sent to authorization uri in query = nonce in current request params): the nonce sent to the auth server is guaranteed to be the same as the nonce in the cookie. So it is sufficient to only check the cookie.
    - Nonce check (cookie = nonce in current request params)
      - `CookieOAuth2AuthorizationRequestRepository` extracts from cookie and creates the `OAuth2AuthorizationRequest`.
      - `OAuth2AuthorizationCodeAuthenticationProvider` compares with the nonce in current request params
    - HMAC check (already done by `ShopifyRequestAuthenticationFilter`)
    - Check for valid `shop` parameter (see `ShopifyOAuth2AuthorizationCodeAuthenticationProvider`)
  - Step 4: Get an access token:
    - insert shop name into token uri (`ShopifyOAuth2AuthorizationCodeAuthenticationProvider`)
    - add parameters to body (already down by default: `RestClientAuthorizationCodeTokenResponseClient` and `DefaultOAuth2TokenRequestParametersConverter`)
    - process response: `access_token` and `scope` values
      - `DefaultMapOAuth2AccessTokenResponseConverter` (used by `RestClientAuthorizationCodeTokenResponseClient` to parse the response) correctly extracts these values.
      - However, the `scope` string is split with `" "` as delimiter. We need to use `","`.
        - see `ShopifyMapOAuth2AccessTokenResponseConverter`
    - Note: if the authorization server responds with an error, `OAuth2AuthorizationCodeGrantFilter` will redirect to the redirect uri with error params. On the second pass, the filter will not match the request as an authorization response and will let the request continue. Further down the filter chain, if this path (redirect uri) requires the user to be authenticated, the AuthorizationFilter will throw an `AccessDeniedException` because the request didn't come from Shopify.
    - The approved scopes are verified in `ShopifyOAuth2AuthorizationCodeAuthenticationProvider`
  - Step 5: Redirect to your app's UI: ShopifyOAuth2AuthorizationCodeGrantFilter
    - PostOAuth2AuthorizationRedirectStrategy redirects to either
      - the full app url (/shopify?shop={shop}&host={host})
      - or to embedded app url ()

- Scenario 2: The shop is already installed, and we have a token (`/shopify`)
- Step 1: Verify the installation request: See `ShopifyInstallationRequestFilter`
- `AutoOAuthTokenLoaderFilter` finds a token for this shop. If it's invalid, it deletes it and reverts to scenario 1
- In OAuth2AuthorizationRequestRedirectFilter, ShopifyOAuth2AuthorizationRequestResolver returns null, and OAuth2AuthorizationRequestRedirectFilter continues through the chain

- We leverage Spring Security OAuth2 Resource Server to validate the session token

An H2 in-memory database is configured to run when the dev profile is active. 
If desired, an H2-in-memory database can be configured when running integration tests. The single existing integration test activates the test profile.

# TODOs
- `isTokenValid()` method in `AutoOAuthTokenLoaderFilter`
- encode the token in DB
-  build up ShopifyAppRequestCache so that it is a fully functional cookie-based request cache
- ShopifyAccessToken scopes should be a set, not a String
- A way of authenticating non-embedded requests. Currently none, so trying to reach the SPA returns `401`