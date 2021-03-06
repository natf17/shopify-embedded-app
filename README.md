# This project replaces the shopify-spring-boot-embedded-app project

This application enables any Spring web application with Spring Security to become a Shopify app and use Shopify's default OAuth offline access token.

# Running the App

- Uses Spring Security 5.2.0.RELEASE

If you're using the Spring Boot security starter, this translates to version 2.2.X.

## Obtaining Information for Your Shopify App
Once you have a development store, create a private app.

1. Fill out "App name" with the name of your choice.
2. Add your "App URL": 
	- *https://{your-hostname}/install/shopify*
3. For "Whitelisted redirection URL(s)" add:
	- *https://{your-hostname}/login/app/oauth2/code/shopify*

Now that you've created your app, you're given an API key and an API key secret.

4. Copy the API key and API key secret from the Shopify site.
5. Store them, along with the desired scope, in a `.properties` file.

```
ppublica.shopify.security.client.client_id=your-key
ppublica.shopify.security.client.client_secret=your-key-secret
ppublica.shopify.security.client.scope=scope1,scope2,...
```
6. Choose the password that the Spring encryptors will use to encrypt the token and add it to your `.properties` file:

```
ppublica.shopify.security.cipher.password=your-password
```

## Adding the project
If you're using Maven, add the following under the `<dependencies>` element in the pom.xml:

```
<dependency>
   <groupId>com.ppublica.shopify</groupId>
   <artifactId>shopify-embedded-app</artifactId>
   <version>1.0.0-RELEASE</version>
   <scope>compile</scope>
</dependency>
```

## Preparing your Application
1. Make sure your Spring/Spring Boot application can find the security beans in the jar.
```
@ComponentScan(basePackages = {"com.ppublica.shopify.security"})
```
2. Make sure the following beans are in the `ApplicationContext`:
	- `MappingJackson2HttpMessageConverter`
	- `JdbcTemplate`
3. Add the following to your `WebSecurityConfigurerAdapter`:
```
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.anyRequest().authenticated().and()
			.requiresChannel().and()
			.oauth2Login();
	}
}
```
4. Your database is expected to have the following schema:
```
|---------------------------STOREACCESSTOKENS-------------------------------|
|                                                                           |
|id--storeDomain--tokenType--tokenValue--salt--issuedAt--expiresAt--scopes--|
|                                                                           |
|---------------------------------------------------------------------------|
```

5. Make sure you use HTTPS to comply with Shopify's security requirements. 

6. Make sure your app is running and is live at the hostname you specified.


## Result
The following endpoints were registered:

`/install/shopify?shop={your-store-name.myshopify.com}`:
- to log in (and install the app on the given store) either from the browser or the embedded app. This is done via Javascript redirects
- if this endpont is called by Shopify from an embedded app and the store has already been installed, the user will be authomatically authenticated (without any OAuth redirects)
- not including the `shop` parameter will force a redirect

`/init`:
- this is the "login" endpoint where entering the store name in a form will call the installation endpoint with a populated `shop` parameter

`/login/app/oauth2/code/**`:
- all the OAuth authentication processing happens here. This endpoint MUST be invoked by Shopify

`/info`:
- a secure endpoint that displays some useful information about the app:
	- apiKey: the api key for the app
	- shopOrigin: the domain of the store that's currently logged in
	- whether the initial login for the session was done from within an embedded app

`/logout`:
- to log out

# Customize the default paths
Coming soon!
