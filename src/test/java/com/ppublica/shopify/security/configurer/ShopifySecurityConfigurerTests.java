package com.ppublica.shopify.security.configurer;

import javax.servlet.Filter;
import javax.servlet.http.HttpSession;
import javax.sql.DataSource;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.mockito.Mockito.doReturn;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestOperations;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.ppublica.shopify.HttpsRequestPostProcessor;
import com.ppublica.shopify.TestDataSource;
import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configuration.SecurityBeansConfig;
import com.ppublica.shopify.security.configuration.ShopifyPaths;
import com.ppublica.shopify.security.converter.ShopifyOAuth2AccessTokenResponseConverter;
import com.ppublica.shopify.security.service.ShopifyStore;
import com.ppublica.shopify.security.web.ShopifyAuthorizationCodeTokenResponseClient;
import com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;
import com.ppublica.shopify.security.web.ShopifyOAuth2AuthorizationRequestResolver;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@TestPropertySource("classpath:test-application.properties")
@WebAppConfiguration
public class ShopifySecurityConfigurerTests {
	
	// from ShopifyPaths bean, which is initialized with values from properties file
	private String LOGIN_ENDPOINT;

	private String INSTALL_PATH_TO_SHOPIFY;
	private String AUTHORIZATION_REDIRECT_PATH;
	
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
	OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
	
	@Autowired
	private ShopifyHttpSessionOAuth2AuthorizationRequestRepository authorizationRequestRepository;

	MockMvc mockMvc;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger("");
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	

	@Before
	public void setup() throws Exception {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.apply(springSecurity(springSecurityFilterChain))
				.build();
		
		LOGIN_ENDPOINT = shopifyPaths.getLoginEndpoint();
		INSTALL_PATH_TO_SHOPIFY = shopifyPaths.getInstallPath() + "/shopify";
		AUTHORIZATION_REDIRECT_PATH = shopifyPaths.getAuthorizationRedirectPath();
		
		clientSecret = env.getProperty("ppublica.shopify.security.client.client_secret");
		clientId = env.getProperty("ppublica.shopify.security.client.client_id");

		
	}
	
	@After
	public void cleanup() throws Exception {
	}
	
	/*
	 * Should redirect if the request doesn't come from Shopify and no shop parameter is included
	 */
	@Test
	public void redirectWhenRequestShopParamNotPresent() throws Exception {
		this.mockMvc.perform(get(INSTALL_PATH_TO_SHOPIFY).secure(true))
			.andExpect(redirectedUrlPattern("/**" + LOGIN_ENDPOINT))
			.andReturn();
		
	}

	/*
	 * Should provide redirection urls for JS if the request doesn't come from Shopify but a shop parameter is included
	 */
	@Test
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
	@Test
	public void whenAuthEndpointThenFail() throws Exception {
		this.mockMvc.perform(get(AUTHORIZATION_REDIRECT_PATH).with(httpsPostProcessor))
					.andExpect(status().isForbidden());
	}
	
	/*
	 * Access some other protected resource.
	 * Since we are not authenticated, authentication entry point 
	 * should redirect to LOGIN_ENDPOINT
	 */
	@Test
	public void whenProtectedResourceThenRedirect() throws Exception {
		this.mockMvc.perform(get("/products").with(httpsPostProcessor))
					.andExpect(status().is3xxRedirection())
					.andExpect(redirectedUrlPattern("**" + LOGIN_ENDPOINT));
	}
	
	/*
	 * Access LOGIN_ENDPOINT
	 * Should return 200 even if we are not authenticated
	 */
	@Test
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
	 * 		4. The "X-Frame-Options" header is null
	 * 
	 */
	@Test
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
		Assert.assertNull(result.getResponse().getHeaderValue("X-Frame-Options"));
		
	}
	
	/*
	 * When logging in to an existing store or installing a new one from outside 
	 * an embedded app, so the request doesn't come from Shopify...
	 * 
	 * Given: valid shop parameter in "installPath"
	 * Expect: 
	 * 		1. redirect uris are printed
	 * 		2. the user was not authenticated (Anonymous)
	 * 		3. the OAuth2AuthorizationRequest was added 
	 * 
	 */
	@Test
	public void whenStoreExistsAndRequestNotFromShopify_thenShowFirstPage() throws Exception {

	
		MvcResult result = this.mockMvc.perform(get(INSTALL_PATH_TO_SHOPIFY + "?shop=lmdev.myshopify.com&timestamp=dsd&hmac=sdfasrf4324").with(httpsPostProcessor))
					.andExpect(status().is2xxSuccessful())
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://lmdev.myshopify.com/admin/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andReturn();
		
		HttpSession session = result.getRequest().getSession();
		Object securityContext = session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		// The AnonymousAuthenticationToken is not stored in the session
		// See HttpSessionSecurityContextRepository
		Assert.assertNull(securityContext);
		
		Assert.assertNotNull(session.getAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST"));
		Assert.assertNull(result.getResponse().getHeaderValue("X-Frame-Options"));

	}
	
	/*
	 * Installing a new store from an embedded app, so the request came from Shopify...
	 * 
	 * Given: valid shop parameter for new store, and hmac parameter
	 * Expect:
	 * 		1. redirect uris are printed
	 * 		2. user not authenticated
	 * 		3. the OAuth2AuthorizationRequest was added 
	 * 
	 */
	@Test
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
		
		HttpSession session = result.getRequest().getSession();
		Object securityContext = session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		/* The ShopifyOriginToken is removed...
		*  ...and AnonymousAuthenticationToken is not stored in the session
		*  See HttpSessionSecurityContextRepository
		*/
		Assert.assertNull(securityContext);
		
		Assert.assertNotNull(session.getAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST"));
		Assert.assertNull(result.getResponse().getHeaderValue("X-Frame-Options"));
	
	}
	
	/*
	 * Installing a new store from outside an embedded app, so the request doesn't come from Shopify...
	 * 
	 * Given: valid shop parameter for new store
	 * Expect:
	 * 		1. redirect uris are printed
	 * 
	 */
	@Test
	public void whenStoreDoesNotExistAndRequestNotFromShopify_thenRedirectToShopify() throws Exception {
	
		MvcResult result = this.mockMvc.perform(get(INSTALL_PATH_TO_SHOPIFY + "?shop=newstoretest.myshopify.com&timestamp=dsd&hmac=sdfasrf4324").with(httpsPostProcessor))
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://newstoretest.myshopify.com/admin/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=test-client-id&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andReturn();
		
		Object securityContext = result.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		// The AnonymousAuthenticationToken is not stored in the session
		// See HttpSessionSecurityContextRepository
		Assert.assertNull(securityContext);
		Assert.assertNull(result.getResponse().getHeaderValue("X-Frame-Options"));

	}
	
	
	
	/*
	 * The request doesn't have a valid shop parameter...
	 * 
	 * Expect:
	 * 		1. redirect
	 * 
	 */
	@Test
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
	 * 	- In step 2, Shopify responds by sending the authorization code in the url. Our application
	 * 	  must query the tokenUri and extract the response
	 * 
	 * 
	 * 
	 */
	
	
	
	/* 
	 * 
	 * We check to make sure our application responded appropriately when Shopify sent the authorization
	 * code. 
	 * 
	 * Given: 
	 * 	- valid Shopify call to our authorizationUri
	 * 	- OAuth2AuthorizationRequest was saved in the session in step 1
	 * 	- Shopify returns a valid body when its tokenUri is invoked
	 * 
	 * Check:
	 * 
	 * 1. We landed at the default page, as generated by DefaultAuthorizationRedirectPathFilter
	 * 2. There's a OAuth2AuthenticationToken in the session
	 * 3. OAuth2AuthenticationToken has correct values:
	 * 		OAuth2AuthenticationToken
	 * 			- Collection<GrantedAuthority>: authorities returned by shopify
	 * 			- name: store domain
	 * 			- OAuth2User principal
	 * 				- name: store domain
	 * 				- 2 attributes:
	 * 					- ShopifyStore.ACCESS_TOKEN_KEY = oauth token
	 * 					- ShopifyStore.API_KEY = client id
	 * 
	 * 
	 */
	
	@SuppressWarnings("unchecked")
	@Test
	@DirtiesContext
	public void whenShopifyReturnsCodeThenObtainTokenAndProcess() throws Exception {
		
		/* Assume the server responds when it receives a request
		 * 
		 * {
		 *     "access_token": \"access-token-1234",
		 *     "scope": "read,write"
		 * }
		 * 
		 */
		HashMap<String,String> responseParams = new HashMap<>();
		responseParams.put("access_token", "access-token-1234");
		responseParams.put("scope", "read,write");

		RestOperations mockRestOperations = mock(RestOperations.class);
		doReturn(getResponseEntity(responseParams)).when(mockRestOperations).exchange(any(), any(Class.class));
		
		// Modify the ShopifyAuthorizationCodeTokenResponseClient bean to use the mock
		ShopifyAuthorizationCodeTokenResponseClient shopifyAccessTokenResponseClient = (ShopifyAuthorizationCodeTokenResponseClient)accessTokenResponseClient;
		shopifyAccessTokenResponseClient.setRestOperations(mockRestOperations);
		
		// Prepare the request values that Shopify would send with the authorization code
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

		// Extract the session object that contains the OAuth2AuthorizationRequest attribute...
		String attributeName = ShopifyHttpSessionOAuth2AuthorizationRequestRepository.DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;
		HttpSession session = request.getSession();
		Object sessionAtrValue = session.getAttribute(attributeName);
		
		
		// Assertions
		
		
		// 1. We landed at the default authorization page
		MvcResult result = this.mockMvc.perform(get(request.getServletPath() + fullQuery).sessionAttr(attributeName, sessionAtrValue).with(httpsPostProcessor))
				.andExpect(content().string(containsString("Authentication/installation SUCCESS!")))
				.andReturn();
		
		// 2. There's a OAuth2AuthenticationToken in the session
		Object securityContext = result.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
		Assert.assertNotNull(securityContext);
		Authentication authentication = ((SecurityContext)securityContext).getAuthentication();
		Assert.assertTrue(authentication instanceof OAuth2AuthenticationToken);
		
		
		// 3. OAuth2AuthenticationToken has correct values
		OAuth2AuthenticationToken token = (OAuth2AuthenticationToken)authentication;
		Assert.assertEquals("shopify", token.getAuthorizedClientRegistrationId());
		
		Collection<GrantedAuthority> auths = token.getAuthorities();
		Assert.assertEquals(2, auths.size());
		
		Assert.assertEquals("testStore", token.getName());
		
		OAuth2User principal = (OAuth2User)token.getPrincipal();
		Assert.assertEquals("testStore", principal.getName());
		Assert.assertEquals("access-token-1234", principal.getAttributes().get(ShopifyStore.ACCESS_TOKEN_KEY));
		Assert.assertEquals(this.clientId, principal.getAttributes().get(ShopifyStore.API_KEY));
			
		
	}
	
	private ResponseEntity<OAuth2AccessTokenResponse> getResponseEntity(Map<String,String> params) {
		ShopifyOAuth2AccessTokenResponseConverter conv = new ShopifyOAuth2AccessTokenResponseConverter();
		return ResponseEntity.ok(conv.convert(params));
		
	}
	
	/*
	 * The ClientRegistration used must have the same client id, client secret, and registration id as 
	 * the bean in SecurityBeansConfig so ShopifyVerificationStrategy can "find" it.
	 * 
	 * However, its token uri isn't used... OAuth2LoginAuthenticationFilter uses the ClientRegistration in
	 * the ClientRegistrationRepository.
	 */
	private OAuth2AuthorizationRequest getTestOAuth2AuthorizationRequest(String shopName, String state) {
		
		// create the OAuth2AuthorizationRequest as ShopifyOAuth2AuthorizationRequestResolver would
		ClientRegistration cR =  ClientRegistration.withRegistrationId("shopify")
				.clientId(this.clientId)
				.clientSecret(this.clientSecret)
				.clientAuthenticationMethod(ClientAuthenticationMethod.POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
				.scope("read", "write")
				.authorizationUri("https://{shop}/admin/oauth/authorize")
				.tokenUri("not-used")
				.clientName("client-1")
				.build();
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, cR.getRegistrationId());
		additionalParameters.put(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN, shopName);
		
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "shopify");
		
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.clientId(cR.getClientId())
				.authorizationUri("https://" + shopName + "/admin/oauth/authorize")
				.redirectUri("https://localhost/login/app/oauth2/code/shopify")
				.scopes(cR.getScopes())
				.state(state)
				.additionalParameters(additionalParameters)
				.attributes(attributes)
				.build();
		
		return authorizationRequest;
		
	}
	
	

	@EnableWebSecurity
	static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {

			/* minimum requirements... if not using defaults:
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
				.requiresChannel().and()
				.oauth2Login();
		}
	}
	
	@EnableWebMvc
	@Configuration
	@Import(SecurityBeansConfig.class)
	static class WebMvcConfig implements WebMvcConfigurer {
		
		@Bean
		TestDataSource testDataSource() {
			return new TestDataSource("shopifysecuritytest");
		}
		
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
		public JdbcTemplate getJdbcTemplate(CipherPassword cP, TestDataSource tds) {
			DataSource dataSource = tds;
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

