package com.lm.security.oauth2.integration;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.handler;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import static org.mockito.Mockito.doReturn;
import static org.mockito.ArgumentMatchers.any;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.lm.security.oauth2.integration.config.HttpsRequestPostProcessor;
import com.lm.security.oauth2.integration.config.TestConfig;
import com.ppublica.shopify.ShopifyEmbeddedAppSpringBootApplication;
import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configuration.SecurityConfig;

/*
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
 * 2. NullShopifyVerificationService (mock)
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes= {ShopifyEmbeddedAppSpringBootApplication.class, TestConfig.class})
@AutoConfigureMockMvc
@TestPropertySource(locations="classpath:test-application.properties")
public class Step1_AuthorizationRequest {

	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	private JdbcTemplate jdbc; 
	
	@Autowired
	private CipherPassword cipherPassword;
	
	@MockBean
	private ShopifyVerificationStrategy strategyMock;
	
	private HttpsRequestPostProcessor httpsPostProcessor = new HttpsRequestPostProcessor();
	
	private static final String INSTALL_PATH = SecurityConfig.INSTALL_PATH + "/shopify";
	
	@Before
	public void initializeValue() {
		String sampleSalt = KeyGenerators.string().generateKey();
		TextEncryptor encryptor = Encryptors.queryableText(cipherPassword.getPassword(), sampleSalt);

		jdbc.update("UPDATE STOREACCESSTOKENS SET access_token=?, salt=? WHERE shop='lmdev.myshopify.com'", encryptor.encrypt("sample"), sampleSalt);
		
	}

	/*
	 * We assume the request came from Shopify, so pertinent parameters are not checked.
	 * 
	 * Given: valid shop parameter in "installPath"
	 * Expect: 
	 * 		1. the user is successfully authenticated
	 * 		2. redirect uris are not printed
	 * 		3. the user has been successfully authenticated with a OAuth2AuthenticationToken
	 * 
	 */
	@Test
	public void whenStoreExistsAndRequestFromShopify_thenAuthenticateAndShowFirstPage() throws Exception {
		doReturn(true).when(strategyMock).isShopifyRequest(any());
		doReturn(true).when(strategyMock).hasValidNonce(any());
	
		MvcResult result = this.mockMvc.perform(get(INSTALL_PATH + "?shop=lmdev.myshopify.com&timestamp=dsd&hmac=sdfasrf4324").secure(true).with(httpsPostProcessor))
					.andExpect(status().is2xxSuccessful())
					.andExpect(handler().methodName("installAndHome"))
					.andExpect(content().string(not(containsString("var redirectFromParentPath = 'https://newstoretest.myshopify.com/admin/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state="))))
					.andExpect(content().string(not(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state="))))
					.andReturn();
		
		
		Object authentication = result.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
		Assert.assertTrue(((SecurityContext)authentication).getAuthentication().getClass().isAssignableFrom(OAuth2AuthenticationToken.class));
	}
	
	/*
	 * The request doesn't come from Shopify...
	 * 
	 * Given: valid shop parameter in "installPath"
	 * Expect: 
	 * 		1. redirect uris are printed
	 * 		2. the user was not authenticated (Anonymous)
	 * 
	 */
	@Test
	public void whenStoreExistsAndRequestNotFromShopify_thenShowFirstPage() throws Exception {

	
		MvcResult result = this.mockMvc.perform(get(INSTALL_PATH + "?shop=lmdev.myshopify.com&timestamp=dsd&hmac=sdfasrf4324").secure(true).with(httpsPostProcessor))
					.andExpect(status().is2xxSuccessful())
					.andExpect(handler().methodName("installAndHome"))
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://lmdev.myshopify.com/admin/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andReturn();
		
		Object authentication = result.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		// The AnonymousAuthenticationToken is not stored in the session
		// See HttpSessionSecurityContextRepository
		Assert.assertNull(authentication);
	}

	/*
	 * We assume the request came from Shopify, so pertinent parameters are not checked.
	 * 
	 * Given: valid shop parameter for new store
	 * Expect:
	 * 		1. redirect uris are printed
	 * 		2. user not authenticated
	 * 
	 */
	@Test
	public void whenStoreDoesNotExistAndRequestFromShopify_thenRedirectToShopify() throws Exception {
		doReturn(true).when(strategyMock).isShopifyRequest(any());
		doReturn(true).when(strategyMock).hasValidNonce(any());
		doReturn(true).when(strategyMock).isHeaderShopifyRequest(any(), any());
	
		MvcResult result = this.mockMvc.perform(get(INSTALL_PATH + "?shop=newstoretest.myshopify.com&timestamp=dsd&hmac=sdfasrf4324").secure(true).with(httpsPostProcessor))
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://newstoretest.myshopify.com/admin/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andReturn();
		
		Object authentication = result.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		/* The ShopifyOriginToken is removed...
		*  ...and AnonymousAuthenticationToken is not stored in the session
		*  See HttpSessionSecurityContextRepository
		*/
		Assert.assertNull(authentication);
	}
	
	
	/*
	 * The request doesn't come from Shopify...
	 * 
	 * Given: valid shop parameter for new store
	 * Expect:
	 * 		1. redirect uris are printed
	 * 
	 */
	@Test
	public void whenStoreDoesNotExistAndRequestNotFromShopify_thenRedirectToShopify() throws Exception {
	
		MvcResult result = this.mockMvc.perform(get(INSTALL_PATH + "?shop=newstoretest.myshopify.com&timestamp=dsd&hmac=sdfasrf4324").secure(true).with(httpsPostProcessor))
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://newstoretest.myshopify.com/admin/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
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
	@Test
	public void whenNoValidShopParam_thenRedirect() throws Exception {
	
		this.mockMvc.perform(get(INSTALL_PATH + "?timestamp=dsd&hmac=sdfasrf4324").secure(true).with(httpsPostProcessor))
					.andExpect(status().is3xxRedirection())
					.andReturn();

		
	}


}