package com.lm.security.oauth2.integration;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;


import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;


import javax.servlet.http.HttpSession;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.lm.security.oauth2.integration.config.HttpsRequestPostProcessor;
import com.lm.security.oauth2.integration.config.TestConfig;
import com.ppublica.shopify.security.web.ShopifyAuthorizationCodeTokenResponseClient;
import com.ppublica.shopify.ShopifyEmbeddedAppSpringBootApplication;
import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;

/*
 * Test the third "step": once we have the authorization code, POST to obtain the token from Shopify
 * 
 * 	- In step 1, we redirected to Shopify for authorization
 * 	- In step 2, Shopify responds by sending the authorization code in the url
 *  ... In step 3, we prepare a POST request to obtain the OAuth token
 * 
 * We stop right when we are about to request the OAuth token from Shopify.
 * 
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes= {ShopifyEmbeddedAppSpringBootApplication.class, TestConfig.class})
@TestPropertySource(locations="classpath:test-application.properties")
@AutoConfigureMockMvc
public class Step3_AccessToken_ShopifyAuthorizationCodeTokenResponseClient_Test {
	
	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
	
	@Autowired
	private JdbcTemplate jdbc; 
	
	@Autowired
	private CipherPassword cipherPassword;
	
	@MockBean
	private ShopifyVerificationStrategy strategyMock;
	
	private HttpsRequestPostProcessor httpsPostProcessor = new HttpsRequestPostProcessor();
	
	private String SESSION_ATTRIBUTE_NAME = HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";
	
	private OAuth2AuthorizationCodeGrantRequest caughtAuthorizationCodeGrantRequest;
	
	private String CODE = "sample_code_returned_by_Shopify";
	
	private String HMAC = "da9d83c171400a41f8db91a950508985";
	
	private String TIMESTAMP = "1409617544";
	
	private String SHOP = "newstoretest.myshopify.com";

	private String SHOPIFY_TOKEN_URI = "https://" + SHOP + "/admin/oauth/access_token";
	
	
	/*
	 * Perform the initial Authorization request and grab objects stored in the HttpSession
	 * that will be used to "continue" the session in the test.
	 * 
	 * Capture the OAuth2AuthorizationCodeGrantRequest passed into OAuth2AccessTokenResponseClient.getTokenResponse(...)
	 * to test our token client.
	 * 
	 */
	@SuppressWarnings("unchecked")
	@Before
	public void initializeValue() throws Exception {
		doReturn(true).when(strategyMock).isShopifyRequest(any());
		doReturn(true).when(strategyMock).hasValidNonce(any());

		String sampleSalt = KeyGenerators.string().generateKey();
		TextEncryptor encryptor = Encryptors.queryableText(cipherPassword.getPassword(), sampleSalt);

		jdbc.update("UPDATE STOREACCESSTOKENS SET access_token=?, salt=? WHERE shop='lmdev.myshopify.com'", encryptor.encrypt("sample"), sampleSalt);
		
		
		// Part 1 - shop will install app, save OAuth2AuthorizationRequest in the session. We retrieve it.
		MvcResult mR = this.mockMvc.perform(get("/install/shopify?shop=newstoretest.myshopify.com&timestamp=dsd&hmac=sdfasrf4324").secure(true).with(httpsPostProcessor)).andReturn();

		HttpSession rSession = mR.getRequest().getSession();
		
		Map<String, OAuth2AuthorizationRequest> oAuth2AuthorizationRequests = (Map<String, OAuth2AuthorizationRequest>)rSession.getAttribute(SESSION_ATTRIBUTE_NAME);
	
		Iterator<Entry<String, OAuth2AuthorizationRequest>> it = oAuth2AuthorizationRequests.entrySet().iterator();
		
		String state = it.next().getKey();
		
		// Prepare the session for part 2.
		MockHttpSession session = new MockHttpSession();
		session.setAttribute(SESSION_ATTRIBUTE_NAME, oAuth2AuthorizationRequests);
		

		
		// Part 2 - Shopify redirects to us, we prepare POST request

		when(accessTokenResponseClient.getTokenResponse(ArgumentMatchers.any())).thenThrow(new OAuth2AuthorizationException(new OAuth2Error("502")));
		
		this.mockMvc.perform(get("/login/app/oauth2/code/shopify?code=" + CODE + "&hmac=" + HMAC + "&timestamp=" + TIMESTAMP + "&state=" + state + "&shop=" + SHOP).session(session).secure(true).with(httpsPostProcessor)).andReturn();

		ArgumentCaptor<OAuth2AuthorizationCodeGrantRequest> grantRequest = ArgumentCaptor.forClass(OAuth2AuthorizationCodeGrantRequest.class);
		

		verify(accessTokenResponseClient).getTokenResponse(grantRequest.capture());

		// Before obtaining the OAuth token, capture the OAuth2AuthorizationCodeGrantRequest
		caughtAuthorizationCodeGrantRequest = grantRequest.getValue();	
		
	}
	
	
	
	/*
	 * We test the ShopifyAuthorizationCodeTokenResponseClient to make sure it passes correct
	 * information to the converter that will actually write the body of the POST request for 
	 * the OAuth token.
	 * 
	 * Make sure:
	 * 
	 * 1. The uri is correct (it's the Shopify token uri)
	 * 2. This is a POST
	 * 3. The body contains the following parameters: 
	 * 		- client_id: The API key for the app, as defined in the Partner Dashboard.
	 * 		- client_secret: The API secret key for the app, as defined in the Partner Dashboard.
	 * 		- code: The same code sent back by SHOPIFY
	 */
	
	@SuppressWarnings("unchecked")
	@Test
	public void givenOAuth2AuthorizationCodeGrantRequest_theFormHttpMessageConverterCreatesValidTokenRequest() throws Exception {

		ShopifyAuthorizationCodeTokenResponseClient oAuth2AccessTokenResponseClient = new ShopifyAuthorizationCodeTokenResponseClient();

		
		// we don't want the converter to write anything at this point
		FormHttpMessageConverter mockConverter = mock(FormHttpMessageConverter.class);
		
		when(mockConverter.canWrite(any(Class.class), any())).thenReturn(true);
		
		doThrow(new RuntimeException("TEST _ EXPECTED EXCEPTION")).when(mockConverter).write(any(), any(), any());
		
		
		// Set the mock converter in the tokenResponseClient
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(mockConverter));
		
		oAuth2AccessTokenResponseClient.setRestOperations(restTemplate);

		// Use the authorizationCodeGrantRequest from step 2 to "get" a token response
		try {
			// The converter should throw an exception
			oAuth2AccessTokenResponseClient.getTokenResponse(this.caughtAuthorizationCodeGrantRequest);
			
		} catch(RuntimeException e) {
			// expected
		}
		
		ArgumentCaptor<MultiValueMap<String,?>> requestParamsMapCapt = ArgumentCaptor.forClass(MultiValueMap.class);
		
		ArgumentCaptor<HttpOutputMessage> outputMessageCapt = ArgumentCaptor.forClass(HttpOutputMessage.class);
		
		// the mock converter was invokeds
		verify(mockConverter).write(requestParamsMapCapt.capture(), any(), outputMessageCapt.capture());
		
		
		
		ClientHttpRequest requestCapt = (ClientHttpRequest)outputMessageCapt.getValue();
		
        // 1. The uri is correct (it's the Shopify token uri)
		Assert.assertEquals(SHOPIFY_TOKEN_URI, requestCapt.getURI().toURL().toString());
		
		// 2. This is a POST
		Assert.assertEquals(HttpMethod.POST, requestCapt.getMethod());
		
		MultiValueMap<String,?> requestParamsMap = requestParamsMapCapt.getValue();
		
		// 3. The body contains the necessary parameters
		Assert.assertTrue(requestParamsMap.containsKey("client_id"));
		Assert.assertTrue(requestParamsMap.containsKey("client_secret"));
		Assert.assertTrue(requestParamsMap.containsKey("code"));

		
	}
	

}
