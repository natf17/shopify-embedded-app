package com.ppublica.shopify.security.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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


/**
 * This filter allows a user to "automatically" log into an existing store without having to go through the 
 * OAuth flow again.
 * <p>This filter matches the installation path (/install/shopify) and checks the SecurityContextHolder for a 
 * ShopifyOriginToken to determine whether this request came from Shopify.</p>
 * 
 * <p>If it did, this filter attempts to find a token for the store and set it as the Authentication. By default, 
 * it uses ShopifyOAuth2AuthorizedClientService to load the OAuth2AuthorizedClient.</p>
 * 
 * <p>This filter ensures that after this filter, the request has no ShopifyOriginToken. The Authentication will 
 * either be null, or an OAuth2AuthenticationToken.</p>
 * 
 * @author N F
 * @see com.ppublica.shopify.security.configuration.ShopifyPaths
 * @see com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer
 * @see com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy
 */
public class ShopifyExistingTokenFilter extends GenericFilterBean {
	private final Log logger = LogFactory.getLog(ShopifyExistingTokenFilter.class);

	private OAuth2AuthorizedClientService clientService;
	private AntPathRequestMatcher requestMatcher;
	private static final String REGISTRATION_ID = SecurityBeansConfig.SHOPIFY_REGISTRATION_ID;
	
	/**
	 * Construct a ShopifyExistingTokenFilter
	 * 
	 * @param clientService To obtain the token for the store
	 * @param loginEndpoint The installation path 
	 */
	public ShopifyExistingTokenFilter(OAuth2AuthorizedClientService clientService, String loginEndpoint) {
		this.clientService = clientService;
		this.requestMatcher = loginEndpoint.endsWith(REGISTRATION_ID) ? new AntPathRequestMatcher(loginEndpoint) : new AntPathRequestMatcher(loginEndpoint + "/" + REGISTRATION_ID);
		
	}

	/**
	 * If the request matches this filter, set a OAuth2AuthenticationToken for the store if a ShopifyOriginToken is 
	 * in the SecurityContext. If not, continue the filter chain. ShopifyOriginToken is always removed before 
	 * continuing.
	 * 
	 * @param request The request
	 * @param response The response
	 * @param chain The security filter chain
	 * @throws IOException When invoking chain
	 * @throws ServletException When invoking the chain
	 */
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
				logger.info("Store found! Setting OAuth2AuthenticationToken");
				this.setToken(oauth2Token);
			} else {
				// If the store has not been installed, ShopifyOriginToken is still in the SecurityContextHolder
				// Remove it
				clearAuthentication();
			}
			
		} else {
			// if there's no ShopifyOriginToken, leave whatever Authentication object is there
			logger.debug("Authentication is not of type ShopifyOriginToken");
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
			logger.debug("Unable to find store. No shop name found in request parameters");
			return null;
		}
		
		
		OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(REGISTRATION_ID, shopName);
		
		if(client == null) {
			// this store "has not been installed", or salt and passwords are outdated
			logger.info("The store " + shopName + " has not been installed.");
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
