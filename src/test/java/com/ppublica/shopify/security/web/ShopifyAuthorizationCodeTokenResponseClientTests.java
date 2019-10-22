package com.ppublica.shopify.security.web;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

public class ShopifyAuthorizationCodeTokenResponseClientTests {
	MockWebServer server;
	
	ClientRegistration clientRegistration;
	OAuth2AuthorizationRequest authorizationRequest;
	OAuth2AuthorizationResponse authorizationResponse;
	OAuth2AuthorizationExchange authorizationExchange;
	ShopifyAuthorizationCodeTokenResponseClient tokenResponseClient;
	
	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		String url = this.server.url("/admin/oauth/access_token/testStore").toString();		
		
		this.clientRegistration = ClientRegistration.withRegistrationId("registration-1")
				.clientId("client-1")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
				.scope("read", "write")
				.authorizationUri("https://{shop}/admin/oauth/authorize")
				.tokenUri(url.substring(0, url.length() - 10) + "/{shop}")
				.clientName("client-1")
				.build();
		
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
		additionalParameters.put(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN, "testStore");
		
		
		authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.clientId("client-id")
				.authorizationUri("https://testStore.myshopify.com/admin/oauth/authorize")
				.redirectUri("https://ppublica.com/login/app/oauth2/code/shopify")
				.scopes(new HashSet<>(Arrays.asList("read_products", "write_products")))
				.state("other-statekey")
				.additionalParameters(additionalParameters)
				.build();
		
		authorizationResponse = OAuth2AuthorizationResponse
				.success("code-1234")
				.state("other-statekey")
				.redirectUri("https://ppublica.com/login/app/oauth2/code/shopify")
				.build();
		
		authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
		
		tokenResponseClient = new ShopifyAuthorizationCodeTokenResponseClient();
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}
	
	/* calls correct tokenUri and contains correct form params...
	 * 
	 * Shopify expects:
	 * 	- client_id
	 * 	- client_secret
	 * 	- code
	 * 
	 */
	@Test
	public void getTokenResponseWhenStoreParamPresentThenCallsCorrectTokenUri() throws Exception {
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\",\n" +
				"   \"scope\": \"read write\",\n" +
				"   \"refresh_token\": \"refresh-token-1234\",\n" +
				"   \"custom_parameter_1\": \"custom-value-1\",\n" +
				"   \"custom_parameter_2\": \"custom-value-2\"\n" +
				"}\n";
		
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		
		OAuth2AuthorizationCodeGrantRequest req = new OAuth2AuthorizationCodeGrantRequest(clientRegistration, authorizationExchange);
		
		tokenResponseClient.getTokenResponse(req);
		
		RecordedRequest recordedRequest = this.server.takeRequest();
		String body = recordedRequest.getBody().readUtf8();
		
		Assert.assertEquals("/admin/oauth/access_token/testStore", recordedRequest.getPath());

		Assert.assertTrue(body.contains("client_id="));
		Assert.assertTrue(body.contains("client_secret="));
		Assert.assertTrue(body.contains("code="));
		
	}
	
	
	//missingShopNameThrowsException
	@Test(expected=RuntimeException.class)
	public void getTokenResponseWhenStoreParamMissingThrowsException() throws Exception {
		authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.clientId("client-id")
				.authorizationUri("https://testStore.myshopify.com/admin/oauth/authorize")
				.redirectUri("https://ppublica.com/login/app/oauth2/code/shopify")
				.scopes(new HashSet<>(Arrays.asList("read_products", "write_products")))
				.state("other-statekey")
				.build();
		authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
		
		OAuth2AuthorizationCodeGrantRequest req = new OAuth2AuthorizationCodeGrantRequest(clientRegistration, authorizationExchange);
		
		tokenResponseClient.getTokenResponse(req);
		
	}
	
	//shopInReponseParameter
	@Test
	public void getTokenResponseMustReturnResponseWithShopParam() throws Exception {
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\",\n" +
				"   \"scope\": \"read write\"\n" +
				"}\n";
		
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		
		OAuth2AuthorizationCodeGrantRequest req = new OAuth2AuthorizationCodeGrantRequest(clientRegistration, authorizationExchange);
		
		OAuth2AccessTokenResponse response = tokenResponseClient.getTokenResponse(req);
		
		String shop = (String)response.getAdditionalParameters().get(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN);

		Assert.assertEquals("testStore", shop);
		
	}
	
	
	private MockResponse jsonResponse(String json) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
	}

	
	
}
