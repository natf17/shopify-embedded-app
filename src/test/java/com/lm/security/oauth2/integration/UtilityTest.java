package com.lm.security.oauth2.integration;

import java.util.Arrays;
import java.util.List;


import org.junit.Assert;
import org.junit.Test;
import org.springframework.web.util.UriComponentsBuilder;

import com.ppublica.shopify.security.web.ShopifyRedirectStrategy;

/*
 * Small tests of methods used throughout
 */
public class UtilityTest {

	@Test
	public void givenScopesListShouldReturnCorrectString() {
		List<String> scopes = Arrays.asList("read_inventory", "write_inventory", "read_products", "write_products");
		String expected = "read_inventory,write_inventory,read_products,write_products";
		
		Assert.assertEquals(expected, ShopifyRedirectStrategy.concatenateListIntoCommaString(scopes));
		
	}
	
	@Test
	public void ran() {
		String s1 = "https://newstoretest.myshopify.com/admin/oauth/authorize";
		
		String s2 = UriComponentsBuilder
		.fromUriString(s1).build().toString();
		
		Assert.assertEquals(s1, s2);
		
	}
	
	@Test
	public void ran2() {
		String s1 = "/oauth/authorize";
		
		String s2 = UriComponentsBuilder
		.fromUriString(s1).build().toString();
		
		Assert.assertEquals(s1, s2);
		
		
	}
	

	
	
}
