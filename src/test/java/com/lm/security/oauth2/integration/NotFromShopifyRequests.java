package com.lm.security.oauth2.integration;

import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.lm.security.oauth2.integration.config.TestConfig;
import com.ppublica.shopify.ShopifyEmbeddedAppSpringBootApplication;
import com.ppublica.shopify.security.configuration.SecurityConfig;

/*
 * Test several endpoints to make sure that either the user is redirected or
 * the oauth2 login flow is commenced.
 * 
 * Test preconditions:
 * 
 * 1. ClientRegistration ("shopify")
 * 2. InMemoryClientRegistrationRepository
 * 3. OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> (mock)
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes= {ShopifyEmbeddedAppSpringBootApplication.class, TestConfig.class})
@AutoConfigureMockMvc
@TestPropertySource(locations="classpath:test-application.properties")
public class NotFromShopifyRequests {
	


	
	@Autowired
	private MockMvc mockMvc;
	
	private static final String INSTALL_PATH = SecurityConfig.INSTALL_PATH + "/shopify";
	private static final String LOGIN_ENDPOINT = SecurityConfig.LOGIN_ENDPOINT;
	public static final String AUTHORIZATION_REDIRECT_PATH = SecurityConfig.AUTHORIZATION_REDIRECT_PATH;


	
	/*
	 * Should redirect if the request doesn't come from Shopify and no shop parameter is included
	 */
	@Test
	public void whenShopParamNotPresentThenRedirectToShopify() throws Exception {

		this.mockMvc.perform(get(INSTALL_PATH))
					.andExpect(redirectedUrlPattern("/**" + LOGIN_ENDPOINT));
		
	}

	
	/*
	 * Should provide redirection urls for JS if the request doesn't come from Shopify but a shop parameter is included
	 */
	@Test
	public void whenShopParamPresentThenJSRedirect() throws Exception {
	
		this.mockMvc.perform(get(INSTALL_PATH + "?shop=test.myshopify.com"))
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://test.myshopify.com/admin/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")));
	}
	
	/*
	 * The authorization endpoint MUST be invoked by Shopify ONLY
	 */
	@Test
	public void whenAuthEndpointThenFail() throws Exception {
	
		this.mockMvc.perform(get(AUTHORIZATION_REDIRECT_PATH))
					.andExpect(status().is4xxClientError());
	}
	
	/*
	 * Access some other protected resource.
	 * Since we are not authenticated, authentication entry point 
	 * should redirect to LOGIN_ENDPOINT
	 */
	@Test
	public void whenProtectedResourceThenRedirect() throws Exception {
	
		this.mockMvc.perform(get("/products"))
					.andExpect(status().is3xxRedirection())
					.andExpect(redirectedUrlPattern("**" + LOGIN_ENDPOINT));
	}
	
	
	/*
	 * Access LOGIN_ENDPOINT
	 * Should retuen 200 if we are not authenticated
	 */
	@Test
	public void whenLoginThenOk() throws Exception {
	
		this.mockMvc.perform(get(LOGIN_ENDPOINT))
					.andExpect(status().is2xxSuccessful());
	}
	
}
