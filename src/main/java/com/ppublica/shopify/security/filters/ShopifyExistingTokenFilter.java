package com.ppublica.shopify.security.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import com.ppublica.shopify.security.service.TokenService;
import com.ppublica.shopify.security.authentication.ShopifyOriginToken;
import com.ppublica.shopify.security.configuration.SecurityBeansConfig;
import com.ppublica.shopify.security.service.ShopifyStore;

/* 
 * This filter matches the installation path (/install/shopify) and checks the SecurityContextHolder for a 
 * ShopifyOriginToken to determine whether this request came from Shopify.
 * 
 * If it did, this filter attempts to find a token for the store and set it as the Authentication.
 * By default, it uses ShopifyOAuth2AuthorizedClientService to load the OAuth2AuthorizedClient.
 * 
 * This filter ensures that after this filter, the request has no ShopifyOriginToken.
 * The Authentication will either be null, or an OAuth2AuthenticationToken.
 */

public class ShopifyExistingTokenFilter extends GenericFilterBean {
	
	private OAuth2AuthorizedClientService clientService;
	private AntPathRequestMatcher requestMatcher;
	private static final String REGISTRATION_ID = SecurityBeansConfig.SHOPIFY_REGISTRATION_ID;
	
	public ShopifyExistingTokenFilter(OAuth2AuthorizedClientService clientService, String loginEndpoint) {
		this.clientService = clientService;
		this.requestMatcher = loginEndpoint.endsWith(REGISTRATION_ID) ? new AntPathRequestMatcher(loginEndpoint) : new AntPathRequestMatcher(loginEndpoint + "/" + REGISTRATION_ID);
		
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest) request;
		
		if(!requestMatcher.matches(req)) {
			chain.doFilter(request, response);

			return;

		}
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		OAuth2AuthenticationToken oauth2Token = null;
		
		if(auth != null && auth instanceof ShopifyOriginToken) {
			// this request is to the installation path from an embedded app
			
			oauth2Token = this.getToken(req);
			if(oauth2Token != null) {

				this.setToken(oauth2Token);
			} else {
				// If the store has not been installed, ShopifyOriginToken is still in the SecurityContextHolder
				// Remove it
				clearAuthentication();
			}
			
		} else {
			// if there's no ShopifyOriginToken, leave whatever Authentication object is there
		}
		
		chain.doFilter(request, response);
		
		
	}
	
	private void clearAuthentication() {
		if(SecurityContextHolder.getContext().getAuthentication() instanceof ShopifyOriginToken) {
			SecurityContextHolder.getContext().setAuthentication(null);
		}
	}
	
	private void setToken(OAuth2AuthenticationToken oauth2Token) {

		SecurityContextHolder.getContext().setAuthentication(oauth2Token);
	}
	
	private OAuth2AuthenticationToken getToken(HttpServletRequest request) {
		
		String shopName = request.getParameter(TokenService.SHOP_ATTRIBUTE_NAME);
		
		if(shopName == null || shopName.isEmpty()) {
			return null;
		}
		
		
		OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(REGISTRATION_ID, shopName);
		
		if(client == null) {
			// this store "has not been installed", or salt and passwords are outdated
			return null;
		}

		// create an OAuth2AuthenticationToken
		
		OAuth2AuthenticationToken oauth2Authentication = new OAuth2AuthenticationToken(
				transformAuthorizedClientToUser(client),
				null,
				REGISTRATION_ID);
		
		return oauth2Authentication;
	}
	
	
	private OAuth2User transformAuthorizedClientToUser(OAuth2AuthorizedClient client) {
		String apiKey = client.getClientRegistration().getClientId();
		
		return new ShopifyStore(client.getPrincipalName(),
														  client.getAccessToken().getTokenValue(), apiKey, null);
	}
	
	
	
}
