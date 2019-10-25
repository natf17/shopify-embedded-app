package com.ppublica.shopify.security.configurer;

import javax.servlet.Filter;
import javax.servlet.http.HttpSession;
import javax.sql.DataSource;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.doReturn;
import static org.mockito.ArgumentMatchers.any;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.ppublica.shopify.AppConfig;
import com.ppublica.shopify.HttpsRequestPostProcessor;
import com.ppublica.shopify.TestDataSource;
import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configuration.ShopifyPaths;
import com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;
import com.ppublica.shopify.security.web.ShopifyOAuth2AuthorizationRequestResolver;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@TestPropertySource("classpath:test-application.properties")
@WebAppConfiguration
public class ShopifySecurityConfigurerTests {
	
	// from ShopifyPaths bean, which is initialized with values from properties file
	private String LOGIN_ENDPOINT;
	private String ANY_INSTALL_PATH;
	//private String FAV_ICON = "/favicon.ico";
	private String INSTALL_PATH_TO_SHOPIFY;
	private String AUTHORIZATION_REDIRECT_PATH;
	private String AUTHENTICATION_FAILURE_URI;
	
	// from properties file
	private String clientSecret;
	private String clientId;
	
	private HttpsRequestPostProcessor httpsPostProcessor = new HttpsRequestPostProcessor();
	
	
	@Autowired
	WebApplicationContext wac;
	
	@Autowired
	ShopifyPaths shopifyPaths;
	
	@Autowired
	Environment env;
	
	@Autowired
	Filter springSecurityFilterChain;
	
	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;
	
	@Autowired
	private ShopifyHttpSessionOAuth2AuthorizationRequestRepository authorizationRequestRepository;

	MockWebServer server;
	MockMvc mockMvc;
	String serverURL;

	@Before
	public void setup() throws Exception {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.apply(springSecurity(springSecurityFilterChain))
				.build();
		
		LOGIN_ENDPOINT = shopifyPaths.getLoginEndpoint();
		ANY_INSTALL_PATH = shopifyPaths.getAnyInstallPath();
		INSTALL_PATH_TO_SHOPIFY = shopifyPaths.getInstallPath() + "/shopify";
		AUTHORIZATION_REDIRECT_PATH = shopifyPaths.getAuthorizationRedirectPath();
		AUTHENTICATION_FAILURE_URI = shopifyPaths.getAuthenticationFailureUri();
		
		clientSecret = env.getProperty("ppublica.shopify.security.client.client_secret");
		clientId = env.getProperty("ppublica.shopify.security.client.client_id");
		
		this.server = new MockWebServer();
		this.server.start();
		this.serverURL = this.server.url("/admin/oauth/access_token/testStore").toString();	
		
		
	}
	
	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}
	
	/*
	 * Should redirect if the request doesn't come from Shopify and no shop parameter is included
	 */
	//@Test
	public void redirectWhenRequestShopParamNotPresent() throws Exception {
		this.mockMvc.perform(get(INSTALL_PATH_TO_SHOPIFY).secure(true))
			.andExpect(redirectedUrlPattern("/**" + LOGIN_ENDPOINT))
			.andReturn();
		
	}

	/*
	 * Should provide redirection urls for JS if the request doesn't come from Shopify but a shop parameter is included
	 */
	//@Test
	public void whenShopParamPresentThenJSRedirect() throws Exception {
	
		this.mockMvc.perform(get(INSTALL_PATH_TO_SHOPIFY + "?shop=test.myshopify.com").with(httpsPostProcessor))
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://test.myshopify.com/admin/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andReturn();
	}
	
	/*
	 * The authorization endpoint MUST be invoked by Shopify ONLY
	 * 
	 * Since it's not from Shopify, ShopifyOriginFilter delegates to the AccessDeniedHandler.
	 */
	//@Test
	public void whenAuthEndpointThenFail() throws Exception {
		this.mockMvc.perform(get(AUTHORIZATION_REDIRECT_PATH).with(httpsPostProcessor))
					.andExpect(status().isForbidden());
	}
	
	/*
	 * Access some other protected resource.
	 * Since we are not authenticated, authentication entry point 
	 * should redirect to LOGIN_ENDPOINT
	 */
	//@Test
	public void whenProtectedResourceThenRedirect() throws Exception {
		this.mockMvc.perform(get("/products").with(httpsPostProcessor))
					.andExpect(status().is3xxRedirection())
					.andExpect(redirectedUrlPattern("**" + LOGIN_ENDPOINT));
	}
	
	/*
	 * Access LOGIN_ENDPOINT
	 * Should return 200 even if we are not authenticated
	 */
	//@Test
	public void whenLoginThenOk() throws Exception {
	
		this.mockMvc.perform(get(LOGIN_ENDPOINT).with(httpsPostProcessor))
					.andExpect(status().is2xxSuccessful());
	}
	
	/*
	 * BEGIN OAUTHTESTS
	 * 
	 * 
	 * 
	 * 
	 * Step 1: To the install path : INSTALL_PATH_TO_SHOPIFY
	 * 
	 * 
	 * Test the first "step" in obtaining the access token:
	 * Calling the install path in various situations:
	 * 
	 * 		1. Shopify request, store exists
	 * 		2. Not from Shopify, store exists
	 * 		3. Shopify request, store doesn't exist
	 * 		4. Not from Shopify, store doesn't exist
	 * 
	 * 		5. No valid shop parameter
	 * 
	 * Test preconditions:
	 * 
	 * 1. A test store is in the database.
	 * 
	 * 
	 */
	
	
	
	
	
	/*
	 * The request came from Shopify...
	 * 
	 * Given: valid shop parameter in "installPath"
	 * Expect: 
	 * 		1. the default page is returned
	 * 		2. redirect uris are not printed
	 * 		3. the user has been successfully authenticated with a OAuth2AuthenticationToken
	 * 
	 */
	//@Test
	public void whenStoreExistsAndRequestFromShopify_thenAuthenticateAndShowFirstPage() throws Exception {
		// prepare request "from Shopify"
		String queryNoHmac = "code=code123&shop=lmdev.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		
		String hmacValue = ShopifyVerificationStrategy.hash(clientSecret, queryNoHmac);
		String fullQuery = queryNoHmac + "&" + ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue;
		
		String url = INSTALL_PATH_TO_SHOPIFY + "?" + fullQuery;
			
		MvcResult result = this.mockMvc.perform(get(url).with(httpsPostProcessor))
					.andExpect(status().is2xxSuccessful())
					.andExpect(content().string(containsString("WELCOME")))
					.andExpect(content().string(not(containsString("var redirectFromParentPath = 'https://newstoretest.myshopify.com/admin/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state="))))
					.andExpect(content().string(not(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state="))))
					.andReturn();
		
		
		Object authentication = result.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
		Assert.assertTrue(((SecurityContext)authentication).getAuthentication().getClass().isAssignableFrom(OAuth2AuthenticationToken.class));
		
		
	}
	
	/*
	 * When logging in to an existing store or installing a new one from outside 
	 * an embedded app, so the request doesn't come from Shopify...
	 * 
	 * Given: valid shop parameter in "installPath"
	 * Expect: 
	 * 		1. redirect uris are printed
	 * 		2. the user was not authenticated (Anonymous)
	 * 
	 */
	//@Test
	public void whenStoreExistsAndRequestNotFromShopify_thenShowFirstPage() throws Exception {

	
		MvcResult result = this.mockMvc.perform(get(INSTALL_PATH_TO_SHOPIFY + "?shop=lmdev.myshopify.com&timestamp=dsd&hmac=sdfasrf4324").with(httpsPostProcessor))
					.andExpect(status().is2xxSuccessful())
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://lmdev.myshopify.com/admin/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andReturn();
		
		Object authentication = result.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		// The AnonymousAuthenticationToken is not stored in the session
		// See HttpSessionSecurityContextRepository
		Assert.assertNull(authentication);
	}
	
	/*
	 * Installing a new store from an embedded app, so the request came from Shopify...
	 * 
	 * Given: valid shop parameter for new store, and hmac parameter
	 * Expect:
	 * 		1. redirect uris are printed
	 * 		2. user not authenticated
	 * 
	 */
	//@Test
	public void whenStoreDoesNotExistAndRequestFromShopify_thenRedirectToShopify() throws Exception {
		// prepare request "from Shopify"
		String queryNoHmac = "code=code123&shop=newstoretest.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
				
		String hmacValue = ShopifyVerificationStrategy.hash(clientSecret, queryNoHmac);
		String fullQuery = queryNoHmac + "&" + ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue;
				
		String url = INSTALL_PATH_TO_SHOPIFY + "?" + fullQuery;
	
		MvcResult result = this.mockMvc.perform(get(url).with(httpsPostProcessor))
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://newstoretest.myshopify.com/admin/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andReturn();
		
		Object authentication = result.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		/* The ShopifyOriginToken is removed...
		*  ...and AnonymousAuthenticationToken is not stored in the session
		*  See HttpSessionSecurityContextRepository
		*/
		Assert.assertNull(authentication);
	}
	
	/*
	 * Installing a new store from outside an embedded app, so the request doesn't come from Shopify...
	 * 
	 * Given: valid shop parameter for new store
	 * Expect:
	 * 		1. redirect uris are printed
	 * 
	 */
	//@Test
	public void whenStoreDoesNotExistAndRequestNotFromShopify_thenRedirectToShopify() throws Exception {
	
		MvcResult result = this.mockMvc.perform(get(INSTALL_PATH_TO_SHOPIFY + "?shop=newstoretest.myshopify.com&timestamp=dsd&hmac=sdfasrf4324").with(httpsPostProcessor))
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://newstoretest.myshopify.com/admin/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andReturn();
		
		Object authentication = result.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		// The AnonymousAuthenticationToken is not stored in the session
		// See HttpSessionSecurityContextRepository
		Assert.assertNull(authentication);
	}
	
	
	
	/*
	 * The request doesn't have a valid shop parameter...
	 * 
	 * Expect:
	 * 		1. redirect
	 * 
	 */
	//@Test
	public void whenNoValidShopParam_thenRedirect() throws Exception {
	
		this.mockMvc.perform(get(INSTALL_PATH_TO_SHOPIFY + "?timestamp=dsd&hmac=sdfasrf4324").secure(true).with(httpsPostProcessor))
					.andExpect(status().is3xxRedirection())
					.andReturn();

		
	}
	
	
	/*
	 * 
	 * 
	 * 
	 * 
	 * 
	 * Step 2: ...
	 * 
	 * 
	 * Test the second "step": Shopify calls the redirection uri
	 * 
	 * 	- In step 1, we redirected to Shopify for authorization
	 * 	... In step 2, Shopify responds by sending the authorization code in the url
	 * 
	 * We stop right when we are about to prepare a request to obtain the OAuth token from Shopify.
	 * 
	 * 
	 */
	
	
	
	/* 
	 * 
	 * We check to make sure our application responded appropriately when Shopify sent the authorization
	 * code by checking the object that's going to be used to request the token.
	 * 
	 * We do this by capturing the OAuth2AuthorizationCodeGrantRequest sent to 
	 * OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>, which would
	 * then make the POST request for a token.
	 * 
	 * Check:
	 * 
	 * 1. The OAuth2AccessTokenResponseClient mock was called
	 * 2. The clientId of the ClientRegistration matches the one in TestConfig
	 * 3. The state generated in @Before(AuthorizationRequest) is in OAuth2AuthorizationRequest
	 * 4. The code passed by "Shopify" in the url is in OAuth2AuthorizationRequest
	 * 5. The redirectUri in the OAuth2AuthorizationRequest 
	 * 
	 * If test is successful: the OAuth2AuthorizationCodeGrantRequest has all necessary, correct
	 * information so that the accessTokenResponseClient can request the token from Shopify
	 * 
	 */
	
	@Test
	public void whenShopifyJSRedirectsThenObtainAuthenticationCode() throws Exception {
		/*
		 * Prepare the request values that Shopify would send with the authorization code
		 */
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/login/app/oauth2/code/shopify");
		String queryNoHmac = "code=code123&shop=testStore&state=state123&timestamp=1337178173";
		String hmacValue = ShopifyVerificationStrategy.hash(clientSecret, queryNoHmac);
		String fullQuery = "?" + queryNoHmac + "&" + ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue;

		/*
		 * We expect the call to the installation endpoint to have saved an OAuth2AuthorizationRequest in the session
		 * (see ShopifyOAuth2AuthorizationRequestResolver)
		 */
		OAuth2AuthorizationRequest authorizationRequest = getTestOAuth2AuthorizationRequest("testStore", "state123");
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request);

		/*
		 * Extract the session object that contains the OAuth2AuthorizationRequest attribute...
		 */
		String attributeName = ShopifyHttpSessionOAuth2AuthorizationRequestRepository.DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;
		HttpSession session = request.getSession();
		Object sessionAtrValue = session.getAttribute(attributeName);
		
		// The server responds when it receives a request at /admin/oauth/access_token/testStore
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"scope\": \"read write\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		
		// We landed at the landing page
		
		MvcResult result = this.mockMvc.perform(get(request.getServletPath() + fullQuery).sessionAttr(attributeName, sessionAtrValue).with(httpsPostProcessor))
				.andExpect(content().string(containsString("Authentication/installation SUCCESS!")))
				.andReturn();
		
		RecordedRequest recordedRequest = this.server.takeRequest();
		String body = recordedRequest.getBody().readUtf8();
		
		Assert.assertEquals("/admin/oauth/access_token/testStore", recordedRequest.getPath());

		Assert.assertTrue(body.contains("client_id="));
		Assert.assertTrue(body.contains("client_secret="));
		Assert.assertTrue(body.contains("code="));
		
		
		/*
		Object authentication = result.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		// The AnonymousAuthenticationToken is not stored in the session
		// See HttpSessionSecurityContextRepository
		Assert.assertNull(authentication);
		Assert.assertTrue(authentication instanceof OAuth2AuthenticationToken);
		
		
		*/
				
		
	}
	
	/*
	 * The ClientRegistration used must have the same client id and client secret and registration id as 
	 * the bean in SecurityBeansConfig so ShopifyVerificationStrategy can "find" it
	 */
	private OAuth2AuthorizationRequest getTestOAuth2AuthorizationRequest(String shopName, String state) {
		
		// create the OAuth2AuthorizationRequest as ShopifyOAuth2AuthorizationRequestResolver would
System.out.println(serverURL.substring(0, serverURL.length() - 10) + "/{shop}");
		ClientRegistration cR =  ClientRegistration.withRegistrationId("shopify")
				.clientId(this.clientId)
				.clientSecret(this.clientSecret)
				.clientAuthenticationMethod(ClientAuthenticationMethod.POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
				.scope("read", "write")
				.authorizationUri("https://{shop}/admin/oauth/authorize")
				.tokenUri(serverURL.substring(0, serverURL.length() - 10) + "/{shop}")
				.clientName("client-1")
				.build();
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, cR.getRegistrationId());
		additionalParameters.put(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN, shopName);
		
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.clientId(cR.getClientId())
				.authorizationUri("https://" + shopName + "/admin/oauth/authorize")
				.redirectUri("https://localhost/login/app/oauth2/code/shopify")
				.scopes(cR.getScopes())
				.state(state)
				.additionalParameters(additionalParameters)
				.build();
		
		return authorizationRequest;
		
	}
	
	private MockResponse jsonResponse(String json) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
	}

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	@EnableWebSecurity
	static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			/* minimum requirements... if not using defults:
			http.authorizeRequests()
					.mvcMatchers(LOGIN_ENDPOINT).permitAll()
					.mvcMatchers(ANY_INSTALL_PATH).permitAll()
					.mvcMatchers(FAV_ICON).permitAll()
					.anyRequest().authenticated().and()
				.requiresChannel()
					.anyRequest()
						.requiresSecure().and()
					.oauth2Login();
			*/
			
			// minimum requirements with defaults:
			http.authorizeRequests()
					.anyRequest().authenticated().and()
				.requiresChannel()
					.anyRequest()
						.requiresSecure().and()
				.oauth2Login();
		}
	}
	
	@EnableWebMvc
	@Configuration
	@Import(AppConfig.class)
	static class WebMvcConfig implements WebMvcConfigurer {
		
		/*
		 * |-------------------------------------------------STOREACCESSTOKENS-------------------------------------------------------|
		 * |           																										         |
		 * |id------storeDomain----------tokenType------tokenValue-------salt-----issuedAt--expiresAt-----------scopes---------------|
		 * |   'lmdev.myshopify.com'      'BEARER'    'token-value'  'salt-value'   2000      3000   'read_products,write_products'  |
		 * |-------------------------------------------------------------------------------------------------------------------------|
		 * 
		 * Note: the salt and tokenValue are generated dynamically.
		 */
		@Bean
		public JdbcTemplate getJdbcTemplate(CipherPassword cP) {
			DataSource dataSource = new TestDataSource("shopifysecuritytest");
			JdbcTemplate template = new JdbcTemplate(dataSource);
			
			String sampleSalt = KeyGenerators.string().generateKey();
			TextEncryptor encryptor = Encryptors.queryableText(cP.getPassword(), sampleSalt);
			String sampleToken = encryptor.encrypt("token-value");
			
			template.execute("CREATE TABLE STOREACCESSTOKENS(id BIGINT NOT NULL IDENTITY, storeDomain VARCHAR(50) NOT NULL, tokenType VARCHAR(50) NOT NULL, tokenValue VARCHAR(100) NOT NULL, salt VARCHAR(100) NOT NULL, issuedAt BIGINT NOT NULL, expiresAt BIGINT NOT NULL, scopes VARCHAR(200) NOT NULL);");
			template.execute("INSERT INTO STOREACCESSTOKENS(storeDomain,tokenType,tokenValue,salt,issuedAt,expiresAt,scopes) VALUES('lmdev.myshopify.com','BEARER','" + sampleToken + "','" + sampleSalt + "',2000,3000,'read_products,write_products');");
			
			return template;
		}
		
		@Bean
		public MappingJackson2HttpMessageConverter getMappingJackson2HttpMessageConverter() {
			return new MappingJackson2HttpMessageConverter();
		}
		
	}
	
	
	
	
}

