package com.lm.security.authentication;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.util.UriUtils;

import com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;

import org.junit.Assert;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/*
 * Test all methods related to verifying a request came from Shopify
 */
public class ShopifyVerificationStrategyTest {
		
	private final String secret = "6a031b0bd6af4eb";
	private String piece1;
	private String piece2;
	private String stringNoHMAC;
	private String hmacValue;
	private String hmacPiece;
	private ClientRegistration testClientRegistration;
	private String clientId;
	private String registrationId;
	
	@Before
	public void startup() {
		piece1 = "code=fsv";
		piece2 = "shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		stringNoHMAC = piece1 + "&" + piece2;
		hmacValue = ShopifyVerificationStrategy.hash(secret, stringNoHMAC);
		hmacPiece = ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue;
		clientId = "testId";
		registrationId = "shopify";
		
		
		testClientRegistration = ClientRegistration.withRegistrationId(registrationId)
        .clientId(clientId)
        .clientSecret(secret)
        .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
        .scope("read_inventory", "write_inventory", "read_products", "write_products")
        .authorizationUri("https://{shop}/admin/oauth/authorize")
        .tokenUri("https://{shop}/admin/oauth/access_token")
        .clientName("Shopify")
        .build();
	}
	
	
	/*
	 * Given: HttpServletRequest
	 * 			- query with a valid HMAC parameter in the middle of the string
	 * 			- valid HMAC request parameter
	 * 
	 * Expect: isShopifyRequest(req) returns true
	 * 
	 */
	@Test
	public void givenValidHMAC_thenIsShopifyRequest_returnsTrue() {
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));

		// The full query string
		String validCompleteString = piece1 + "&" + hmacPiece + "&" + piece2;
		
		// The HttpServletRequest has the valid HMAC parameter
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		HttpServletRequest req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(validCompleteString);
		when(req.getParameterMap()).thenReturn(paramMap);

		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());
		
		Assert.assertTrue(strategy.isShopifyRequest(req));
		
	}
	
	/*
	 * Given: HttpServletRequest
	 * 			- URL encoded query with a valid HMAC parameter in the middle of the string
	 * 			- valid (decoded) HMAC request parameter
	 * 
	 * Expect: isShopifyRequest(req) returns true
	 * 
	 */
	@Test
	public void givenValidURLEncodedHMAC_thenIsShopifyRequest_returnsTrue() {
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));

		// The full query string
		String validCompleteString = piece1 + "&" + hmacPiece + "&" + piece2;
		
		String urlEncodedQuery = UriUtils.encode(validCompleteString, StandardCharsets.UTF_8);
		
		// The HttpServletRequest has the valid HMAC parameter
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		HttpServletRequest req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(urlEncodedQuery);
		when(req.getParameterMap()).thenReturn(paramMap);

		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());
		
		Assert.assertTrue(strategy.isShopifyRequest(req));
		
	}
	
	
	/*
	 * Given: HttpServletRequest
	 * 			- query with a valid HMAC parameter at the end of the string
	 * 			- valid HMAC request parameter
	 * 
	 * Expect: isShopifyRequest(req) returns true
	 * 
	 */
	@Test
	public void givenValidHMACLastParam_thenIsShopifyRequest_returnsTrue() {
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));

		// The full query string
		String validCompleteString = piece1 + "&" + piece2 + "&" + hmacPiece;
		
		// The HttpServletRequest has the valid HMAC parameter
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		HttpServletRequest req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(validCompleteString);
		when(req.getParameterMap()).thenReturn(paramMap);

		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());
		
		Assert.assertEquals(true, strategy.isShopifyRequest(req));

	}
	

	/*
	 * Given: HttpServletRequest
	 * 			- query with an invalid HMAC parameter in the middle of the string
	 * 			- invalid HMAC request parameter
	 * 
	 * Expect: isShopifyRequest(req) returns false
	 * 
	 */
	@Test
	public void givenInvalidHMAC_thenIsShopifyRequest_returnsFalse() {
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));

		// The wrong hash of the string without the HMAC
		String wrongHmacValue = hmacValue + "asd";
		
		// The query piece with the valid HMAC
		String wrongHmacPiece = ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + wrongHmacValue;

		// The full query string
		String queryInvalidHMAC = piece1 + "&" + wrongHmacPiece + "&" + piece2;
		
		// The HttpServletRequest has the valid HMAC parameter
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {wrongHmacValue});
		
		HttpServletRequest req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(queryInvalidHMAC);
		when(req.getParameterMap()).thenReturn(paramMap);

		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());

		Assert.assertFalse(strategy.isShopifyRequest(req));

	}
	
	
	/*
	 * Given: HttpServletRequest
	 * 			- query with no HMAC parameter
	 * 			- no HMAC request parameter
	 * 
	 * Expect: isShopifyRequest(req) returns false
	 * 
	 */
	@Test
	public void givenNoHMAC_thenIsShopifyRequest_returnsFalse() {
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));

		// The HttpServletRequest has some other parameter
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put("code", new String[] {"fsv"});
		
		HttpServletRequest req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(stringNoHMAC);
		when(req.getParameterMap()).thenReturn(paramMap);

		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());

		Assert.assertEquals(false, strategy.isShopifyRequest(req));
		
	}
	
	
	/*
	 * Given: HttpServletRequest
	 * 			- query with multiple (correct) HMAC parameters
	 * 			- multiple (correct) HMAC request parameters
	 * 
	 * Expect: isShopifyRequest(req) returns false
	 * 
	 */
	@Test
	public void givenMultipleHMAC_thenIsShopifyRequest_returnsFalse() {
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));
		
		// The full query string with multiple HMACs
		String validCompleteString = piece1 + "&" + piece2 + "&" + hmacPiece + "&" + hmacPiece;
		
		// The HttpServletRequest has multiple valid HMAC parameters
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		HttpServletRequest req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(validCompleteString);
		when(req.getParameterMap()).thenReturn(paramMap);


		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());

		Assert.assertEquals(false, strategy.isShopifyRequest(req));
		
	}
	
	
	/*
	 * Given:
	 * 		- JSON body
	 * 		- incorrect HMAC
	 * 
	 * Expect: isShopifyHeaderRequest returns false
	 * 
	 */
	@Test
	public void givenInvalidBody_thenIsHeaderShopifyRequest_returnsFalse() {
		
		ShopifyVerificationStrategy strategy = new ShopifyVerificationStrategy(null, null);
		
		String body = "{\"id\":689034}";
		
		String hmac = Base64.getEncoder().encodeToString(ShopifyVerificationStrategy.hash(this.secret, body).getBytes());

		Assert.assertFalse(strategy.isShopifyHeaderRequest(body + "ds", hmac, secret));
		
	}
	
	
	/*
	 * Given:
	 * 		- JSON body
	 * 		- correct HMAC
	 * 
	 * Expect: isShopifyHeaderRequest returns true
	 */
	@Test
	public void givenValidBody_thenIsHeaderShopifyRequest_returnsTrue() {
		ShopifyVerificationStrategy strategy = new ShopifyVerificationStrategy(null, null);
		
		String body = "{\"id\":689034}";
		
		String hmac = Base64.getEncoder().encodeToString(ShopifyVerificationStrategy.hash(this.secret, body).getBytes());

		Assert.assertTrue(strategy.isShopifyHeaderRequest(body, hmac, this.secret));
	}
	
	
	/*
	 * Given: HttpServletRequest
	 * 			- valid Hmac header
	 * 			- valid body
	 * 		
	 * 		- Valid secret persisted for the request
	 * 
	 * Expect: isHeaderShopifyRequest(req) returns true
	 * 
	 */
	@Test
	public void givenValidBodyRequest_thenIsHeaderShopifyRequest_returnsTrue() {
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null, null));
		
		String body = "{\"id\":689034}";
		String secret = "dfdfbjhew";
		
		String hmac = Base64.getEncoder().encodeToString(ShopifyVerificationStrategy.hash(secret, body).getBytes());
		
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		when(request.getHeader(ShopifyVerificationStrategy.HMAC_HEADER)).thenReturn(hmac);
		
		doReturn(body).when(strategy).getBody(any());
		doReturn(secret).when(strategy).getClientSecretByRegistrationId(any());
		
		Assert.assertTrue(strategy.isHeaderShopifyRequest(request, "registrationId"));
	}
	

	/*
	 * Given: HttpServletRequest
	 * 			- valid Hmac header
	 * 			- invalid body
	 * 		
	 * 		- Valid secret persisted for the request
	 * 
	 * Expect: isHeaderShopifyRequest(req) returns true
	 * 
	 */
	@Test
	public void givenInvalidBodyRequest_thenIsHeaderShopifyRequest_returnsFalse() {
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null, null));
		
		String body = "{\"id\":689034}";
		String secret = "dfdfbjhew";
		
		String hmac = Base64.getEncoder().encodeToString(ShopifyVerificationStrategy.hash(secret, body).getBytes());
		
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		when(request.getHeader(ShopifyVerificationStrategy.HMAC_HEADER)).thenReturn(hmac);
		doReturn(body + "sad").when(strategy).getBody(any());
		doReturn(secret).when(strategy).getClientSecretByRegistrationId(any());
		
		Assert.assertFalse(strategy.isHeaderShopifyRequest(request, "registrationId"));
		
	}
	

	/*
	 * Given: HttpServletRequest
	 * 			- valid nonce parameter
	 * 		
	 * 		- Valid nonce stored in authorizationRequestRepository
	 * 
	 * Expect: hasValidNonce(req) returns true
	 * 
	 */
	@Test
	public void givenValidNonce_thenHasValidNonce_returnsTrue() {
	
		HttpServletRequest request = mock(HttpServletRequest.class);
		String sampleNonce = "4567gf";
		
		ShopifyHttpSessionOAuth2AuthorizationRequestRepository mockAuthReqRepo = mock(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.class);
		Map<String,OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>();
		authorizationRequests.put(sampleNonce, null);
		when(mockAuthReqRepo.getAuthorizationRequests(request)).thenReturn(authorizationRequests);
		
		ShopifyVerificationStrategy svs = new ShopifyVerificationStrategy(null, mockAuthReqRepo);
		
		
		when(request.getParameter(ShopifyVerificationStrategy.NONCE_PARAMETER)).thenReturn(sampleNonce);
		
		Assert.assertTrue(svs.hasValidNonce(request));
	}
	
	
	/*
	 * Given: HttpServletRequest
	 * 			- without nonce parameter
	 * 		
	 * 		- Valid nonce stored in authorizationRequestRepository
	 * 
	 * Expect: hasValidNonce(req) returns false
	 * 
	 */
	@Test
	public void givenMissingNonce_thenHasValidNonce_returnsFalse() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		String sampleNonce = "4567gf";
		
		ShopifyHttpSessionOAuth2AuthorizationRequestRepository mockAuthReqRepo = mock(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.class);
		Map<String,OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>();
		authorizationRequests.put(sampleNonce, null);
		when(mockAuthReqRepo.getAuthorizationRequests(request)).thenReturn(authorizationRequests);
		
		ShopifyVerificationStrategy svs = new ShopifyVerificationStrategy(null, mockAuthReqRepo);
		
		
		when(request.getParameter(ShopifyVerificationStrategy.NONCE_PARAMETER)).thenReturn(null);
		
		Assert.assertFalse(svs.hasValidNonce(request));
	}
	
	
	/*
	 * Given: HttpServletRequest
	 * 			- invalid nonce parameter
	 * 		
	 * 		- Valid nonce stored in authorizationRequestRepository
	 * 
	 * Expect: hasValidNonce(req) returns false
	 * 
	 */
	@Test
	public void givenInvalidNonce_thenHasValidNonce_returnsFalse() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		String sampleNonce = "4567gf";
		String incorrectNonce = sampleNonce + "--";
		
		ShopifyHttpSessionOAuth2AuthorizationRequestRepository mockAuthReqRepo = mock(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.class);
		Map<String,OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>();
		authorizationRequests.put(sampleNonce, null);
		when(mockAuthReqRepo.getAuthorizationRequests(request)).thenReturn(authorizationRequests);
		
		ShopifyVerificationStrategy svs = new ShopifyVerificationStrategy(null, mockAuthReqRepo);
		
		
		when(request.getParameter(ShopifyVerificationStrategy.NONCE_PARAMETER)).thenReturn(incorrectNonce);
		
		Assert.assertFalse(svs.hasValidNonce(request));
	}
	
	/*
	 * Given: HttpServletRequest
	 * 			- nonce parameter
	 * 		
	 * 		- No nonce in authorizationRequestRepository
	 * 
	 * Expect: hasValidNonce(req) returns false
	 * 
	 */
	@Test
	public void givenMissingStoredNonce_thenHasValidNonce_returnsFalse() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		String sampleNonce = "4567gf";
		
		ShopifyHttpSessionOAuth2AuthorizationRequestRepository mockAuthReqRepo = mock(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.class);
		Map<String,OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>();
		when(mockAuthReqRepo.getAuthorizationRequests(request)).thenReturn(authorizationRequests);
		
		ShopifyVerificationStrategy svs = new ShopifyVerificationStrategy(null, mockAuthReqRepo);
		
		
		when(request.getParameter(ShopifyVerificationStrategy.NONCE_PARAMETER)).thenReturn(sampleNonce);
		
		Assert.assertFalse(svs.hasValidNonce(request));
	}
	
	/*
	 * Given: HttpServletRequest
	 * 		
	 * 		- No OAuth2AuthorizationRequest in ShopifyHttpSessionOAuth2AuthorizationRequestRepository
	 * 		- ClientRegistration in ClientRegistrationRepository
	 * 
	 * Expect: 
	 * 		- registration id extracted from request
	 * 		- ClientRegistration found via clientRegistrationRepository.findByRegistrationId
	 * 		- secret extracted from ClientRegistration
	 * 		- getClientSecret(req) returns correct secret
	 * 
	 */
	@Test
	public void givenNoSavedRequest_thenGetClientSecret_extractsSecretFromClientRegistrationRepo() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		ShopifyHttpSessionOAuth2AuthorizationRequestRepository mockAuthReqRepo = mock(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.class);
		when(mockAuthReqRepo.getFirstAuthorizationRequest(request)).thenReturn(null);
		when(mockAuthReqRepo.extractRegistrationId(request)).thenReturn(registrationId);
		
		InMemoryClientRegistrationRepository mockClientRegistrationRepo = new InMemoryClientRegistrationRepository(testClientRegistration);
		
		ShopifyVerificationStrategy svs = new ShopifyVerificationStrategy(mockClientRegistrationRepo, mockAuthReqRepo);

		Assert.assertEquals(secret, svs.getClientSecret(request));
		
	}
	
	
	
	/*
	 * Given: HttpServletRequest
	 * 		
	 * 		- OAuth2AuthorizationRequest in ShopifyHttpSessionOAuth2AuthorizationRequestRepository
	 * 		- ClientRegistration in ClientRegistrationRepository
	 * 
	 * Expect: 
	 * 		- client id extracted from OAuth2AuthorizationRequest
	 * 		- use client id to search InMemoryClientRegistrationRepository
	 * 		- secret extracted from matching ClientRegistration
	 * 		- getClientSecret(req) returns correct secret
	 * 
	 */
	@Test
	public void givenSavedRequest_thenGetClientSecret_extractsSecretFromClientRegistrationRepo() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		OAuth2AuthorizationRequest oauthRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("sampleUri")
				.clientId(clientId).build();
		
		Map<String,OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>();
		authorizationRequests.put("key", oauthRequest);
		
		ShopifyHttpSessionOAuth2AuthorizationRequestRepository mockAuthReqRepo = mock(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.class);
		when(mockAuthReqRepo.getFirstAuthorizationRequest(request)).thenReturn(authorizationRequests.entrySet().iterator().next());
		
		// repo searched for with clientId
		InMemoryClientRegistrationRepository mockClientRegistrationRepo = new InMemoryClientRegistrationRepository(testClientRegistration);
		
		ShopifyVerificationStrategy svs = new ShopifyVerificationStrategy(mockClientRegistrationRepo, mockAuthReqRepo);

		Assert.assertEquals(secret, svs.getClientSecret(request));

		
		//Map.Entry<String, OAuth2AuthorizationRequest> authReqEntry

	}
	
	/*
	 * Given: HttpServletRequest
	 * 		
	 * 		- OAuth2AuthorizationRequest in ShopifyHttpSessionOAuth2AuthorizationRequestRepository
	 * 		- no matching ClientRegistration in ClientRegistrationRepository
	 * 
	 * Expect: 
	 * 		- exception thrown
	 * 
	 */
	@Test(expected=Exception.class)
	public void givenSavedRequest_thenGetClientSecret_throwsException() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		OAuth2AuthorizationRequest oauthRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("sampleUri")
				.clientId(clientId + "other").build();
		
		Map<String,OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>();
		authorizationRequests.put("key", oauthRequest);
		
		ShopifyHttpSessionOAuth2AuthorizationRequestRepository mockAuthReqRepo = mock(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.class);
		when(mockAuthReqRepo.getFirstAuthorizationRequest(request)).thenReturn(authorizationRequests.entrySet().iterator().next());
		
		// repo searched for with clientId
		InMemoryClientRegistrationRepository mockClientRegistrationRepo = new InMemoryClientRegistrationRepository(testClientRegistration);
		
		ShopifyVerificationStrategy svs = new ShopifyVerificationStrategy(mockClientRegistrationRepo, mockAuthReqRepo);

		svs.getClientSecret(request);

	}

	
	/*
	 * Given: String registrationId
	 * 		
	 * 		- ClientRegistrationRepository
	 * 
	 * Expect: 
	 * 		- ClientRegistrationRepository.findRegistrationById() is called
	 * 
	 */
	@Test
	public void givenRegistrationId_thenGetClientSecretByRegistrationId_callsRepo() {
		String registrationId = "shopify";
		
		// repo searched for with clientId
		ClientRegistrationRepository mockClientRegistrationRepo = mock(ClientRegistrationRepository.class);
				
		ShopifyVerificationStrategy svs = new ShopifyVerificationStrategy(mockClientRegistrationRepo, null);
		
		svs.getClientSecretByRegistrationId(registrationId);
		
		verify(mockClientRegistrationRepo).findByRegistrationId(registrationId);

	}
	
	/*
	 * Given: secret
	 * 		  body
	 * 
	 * Expect: 
	 * 		- correct hmac is returned... compared with what's on Shopify website
	 * 
	 */
	@Test
	public void givenSecretAndBody_thenHash_returnsCorrectHash() {
		String secret = "hush";
		String body = "code=0907a61c0c8d55e99db179b68161bc00&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		String expected = "700e2dadb827fcc8609e9d5ce208b2e9cdaab9df07390d2cbca10d7c328fc4bf";
		
		Assert.assertEquals(expected, ShopifyVerificationStrategy.hash(secret, body));
		

	}
	
	
	
	
}