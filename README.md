# Getting started
***************************************

How can we use Shopify's default OAuth offline access token in a Spring Boot app, leveraging the power of Spring Security? This working implementation only requires a few lines in the application.properties file for it to work. It's a server that authenticates with Shopify and, upon successful authentication, keeps the OAuth token, store name, and api key in a session object, which can be used in a variety of ways, such as a single page web application (or React/Polaris).

We assume you know your way around the Shopify developer site to create apps and development stores. Once you have a development store, create a private app.

1. Fill out "App name" with the name of your choice.
2. Add your "App URL": 
	- *https://{your-hostname}/install/shopify*
3. For "Whitelisted redirection URL(s)" add:
	- *https://{your-hostname}/login/app/oauth2/code/shopify*

Now that you've created your app, you're given an API key and an API key secret.

4. Copy the API key and API key secret from the Shopify site.
5. Store them, along with the desired scope, in `application.properties`:

```
shopify.client.client_id=your-key
shopify.client.client_secret=your-key-secret
shopify.client.scope=scope1,scope2,...
```
6. Choose the salt and password that the Spring encryptors will use to encrypt the token and add them to your `application.properties`:

```
lm.security.cipher.password=your-passwords
lm.security.cipher.salt=your-salt
```

7. Whether you're using ngrok, or your own server, make sure you use HTTPS to comply with Shopify's security requirements. 

8. Make sure your app is running and live at the hostname you specified.

9. That's it!

Try out the following endpoints from your browser:
- */install/shopify?shop={your-store-name.myshopify.com}*: to log in (and install the app on the given store)
- */init*: to log in by entering your store in a form
- */products*: a secure endpoint
- */logout*: to log out

For example, say you have a store with the name "mysamplestore".
1. Go to *https://{your-hostname}/install/shopify?shop=mysamplestore.myshopify.com*
2. Follow the instruction on the browser to authenticate.
3. If this is the first time, install the store.
4. If you go to the Shopify Admin for "mysamplestore", under Apps, you should see the new app you installed.
5. Click on the app from the Shopify Admin.
6. This should load the embedded app; by default, you should see "WELCOME".


You can change the defaults in the `SecurityConfig` class in the `com.lm.security.configuration` package.

Note: Once the app is installed, it expects to find a token in the database. If it is lost (for example if the database is in-memory and the server restarts), you will not be able to log in via the embedded app. Access the app directly from a browser, which will trigger the OAuth redirects and save the token in the database. You should then be able to log in as an embedded app.

Note: This Spring Security application requires the Java Cryptography Encryption policy files for encryption.

See https://www.oracle.com/technetwork/java/javase/downloads/jce-all-download-5170447.html

***************************************
# Under the hood
***************************************

A request to */install/shopify* will either:
- redirect to */init* if the request is missing a shop parameter
- pass through with a `OAuth2AuthenticationToken` if the store exists and this is an embedded app
- initiate the OAuth flow. If the request is not coming from an embedded app (regardless of whether or not this app has been installed), or if the request came from an embedded app (and this app has not been installed), the `ShopifyOAuth2AuthorizationRequestResolver` and its helper classes prepare for the first step of the OAuth flow by saving an `OAuth2AuthorizationRequest` in the session, and creating and saving the redirect uris as request attributes for retrieval from the javascript fragment that will redirect.

Assuming the redirect takes place, the OAuth flow begins.

The `OAuth2LoginAuthenticationFilter`/`AbstractAuthenticationProcessingFilter` matches the default *{baseUrl}/login/app/oauth2/code/shopify* and...
1. Retrieves and removes the `OAuth2AuthorizationRequest` saved by `ShopifyHttpSessionOAuth2AuthorizationRequestRepository`
2. Builds an `OAuth2AuthorizationResponse` from the Shopify response parameters
3. Builds an `OAuth2AuthorizationExchange` that contains the `OAuth2AuthorizationRequest` and `OAuth2AuthorizationResponse` 
4. Uses the `OAuth2AuthorizationExchange` along with the corresponding Shopify `ClientRegistration` to build an `OAuth2LoginAuthenticationToken`
5. Delegates to `OAuth2LoginAuthenticationProvider`, which returns a `OAuth2LoginAuthenticationToken`
6. Uses the `OAuth2LoginAuthenticationToken` to create an `OAuth2AuthenticationToken` and an `OAuth2AuthorizedClient`
7. Uses the default `AuthenticatedPrincipalOAuth2AuthorizedClientRepository` (which uses the custom `ShopifyOAuth2AuthorizedClientService`) to save the `OAuth2AuthorizedClient`
8. Calls `sessionStrategy.onAuthentication(...)` on the default `NullAuthenticatedSessionStrategy` (does nothing)
9. Calls `successfulAuthentication(...)` which sets the authentication in the `SecurityContextHolder`, takes care of other services, and finally delegates to the custom `NoRedirectSuccessHandler` successHandler, which forwards to *login/app/oauth2/code*.


The default `OAuth2LoginAuthenticationProvider`...
1. Uses a custom `OAuth2AccessTokenResponseClient`, `ShopifyAuthorizationCodeTokenResponseClient`, to get an `OAuth2AccessTokenResponse`
2. Asks the custom implementation of `OAuth2UserService<OAuth2UserRequest, OAuth2User>`, `DefaultShopifyUserService`, to load the `OAuth2User`.
3. Returns a `OAuth2LoginAuthenticationToken` using the `ClientRegistration`, `AuthorizationExchange`, `OAuth2User`, ...

