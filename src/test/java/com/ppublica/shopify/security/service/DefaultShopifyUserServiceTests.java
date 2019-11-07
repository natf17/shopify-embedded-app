package com.ppublica.shopify.security.service;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.ppublica.shopify.security.web.ShopifyOAuth2AuthorizationRequestResolver;

public class DefaultShopifyUserServiceTests {
	
ClientRegistration clientRegistration;
	
	@Before
	public void setup() {
		clientRegistration = ClientRegistration.withRegistrationId("shopify")
	            .clientId("client-id")
	            .clientSecret("client-secret")
	            .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
	            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	            .redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
	            .scope("read_products", "write_products")
	            .authorizationUri("https://{shop}/admin/oauth/authorize")
	            .tokenUri("https://{shop}/admin/oauth/access_token")
	            .clientName("Shopify")
	            .build();
	}


	@Test
	public void loadUserReturnsStore() {
		DefaultShopifyUserService service = new DefaultShopifyUserService();
		
		OAuth2UserRequest req = mock(OAuth2UserRequest.class);
		
		HashMap<String,Object> additionalParams = new HashMap<>();
		additionalParams.put(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN, "test-store");
		
		OAuth2AccessToken token = mock(OAuth2AccessToken.class);
		when(token.getTokenValue()).thenReturn("token-value");
		when(token.getScopes()).thenReturn(new HashSet<>(Arrays.asList("read", "write")));

		when(req.getAdditionalParameters()).thenReturn(additionalParams);
		when(req.getClientRegistration()).thenReturn(clientRegistration);
		when(req.getAccessToken()).thenReturn(token);
		
		OAuth2User user = service.loadUser(req);
	
		Assert.assertEquals("test-store", user.getName());
		Assert.assertEquals("token-value", user.getAttributes().get(ShopifyStore.ACCESS_TOKEN_KEY));
		Assert.assertEquals("client-id", user.getAttributes().get(ShopifyStore.API_KEY));
		
		Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
		Assert.assertEquals(2, authorities.size());
		Assert.assertTrue(authorities.contains(new SimpleGrantedAuthority("read")));
		Assert.assertTrue(authorities.contains(new SimpleGrantedAuthority("write")));

		
	}

}
