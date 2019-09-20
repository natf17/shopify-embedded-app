package com.lm.security.filters.integration;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.ppublica.shopify.ShopifyEmbeddedAppSpringBootApplication;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;

/*
 * Ensure proper behavior when Shopify sends a POST request to the uninstall url
 * 
 * Test preconditions from config classes:
 *
 * 1. NullVerificationStrategy - the header isn't inspected
 * 
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,classes= {ShopifyEmbeddedAppSpringBootApplication.class})
@TestPropertySource(locations="classpath:test-application.properties")
@AutoConfigureMockMvc
public class UninstallStoreTest {

	@MockBean
	private ShopifyVerificationStrategy strategyMock;
	
	@Autowired
	private MockMvc mockMvc;
	
	@Before
	public void init() {
		doReturn(true).when(strategyMock).isHeaderShopifyRequest(any(), any());
	}
	
	/*
	 * As long as the request is valid (valid body and came from Shopify), it should return 200
	 */
	@Test
	public void whenValidRequest_thenExtractBody() throws Exception {
		this.mockMvc.perform(post("/store/uninstall/shopify").secure(true).content("{\"shop_id\": 954889,\"shop_domain\": \"snowdevil.myshopify.com\"}")).andExpect(status().is(200));
		
	}
	
	/*
	 * Missing part of body
	 * 
	 * Expect: 403
	 */
	@Test
	public void whenNoStore_thenFail() throws Exception {
		this.mockMvc.perform(post("/store/uninstall/shopify").secure(true).content("{\"shop_id\": 954889}")).andExpect(status().is(403));
		
		
	}
}
