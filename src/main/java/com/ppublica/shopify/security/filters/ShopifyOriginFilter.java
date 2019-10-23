package com.ppublica.shopify.security.filters;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.ppublica.shopify.security.authentication.ShopifyOriginToken;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;

/*
 * This filter checks the request to see if it came from Shopify.
 * It only checks the paths passed in via the constructor.
 * It delegates to ShopifyVerificationStrategy to:
 * 		- check the HMAC (/install/** and /login/app/oauth2/code/**)
 * 		- check for a valid nonce (/login/app/oauth2/code/**)
 * 
 * It never replaces a OAuth2AuthenticationToken if it's the Authentication object for the session.
 * 
 * If the request matches the authorizationPath (/login/app/oauth2/code/**), it must be from Shopify and 
 * contain the valid nonce. If not, it uses accessDeniedHandler to generate a 403 error.
 * 
 * For any other matching path (/install/**), it populates the SecurityContext with a ShopifyOriginToken
 * if and only if it came from Shopify.
 * 
 * Also, for requests to the installation path (/install/**), a session attribute is set to indicate that 
 * this is an embedded app:
 * 
 * session.addAttribute("SHOPIFY_EMBEDDED_APP", true);
 * 
 * It is ADDED in the following situations:
 *  - If the request came from Shopify, whether or not the user is authenticated with a OAuth2AuthenticationToken
 * 
 * It is REMOVED in the following situations:
 *  - If the user is not authenticated with a OAuth2AuthenticationToken AND the request did not come from Shopify
 *  
 *  It will remain unchanged if the user is already authenticated and the request did not come from Shopify.
 *  If it had the attribute, it'll remain. It it didn't have it, it will not be added. 

 */
public class ShopifyOriginFilter implements Filter {
	private AntPathRequestMatcher mustComeFromShopifyMatcher;
	private List<AntPathRequestMatcher> applicablePaths;
	private ShopifyVerificationStrategy shopifyVerificationStrategy;
	private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
	public static String SHOPIFY_EMBEDDED_APP = "SHOPIFY_EMBEDDED_APP";
	
	public ShopifyOriginFilter(ShopifyVerificationStrategy shopifyVerificationStrategy, String authorizationPath, String... maybeUris) {
		this.mustComeFromShopifyMatcher = new AntPathRequestMatcher(authorizationPath);
		this.shopifyVerificationStrategy = shopifyVerificationStrategy;
		
		applicablePaths = new ArrayList<>();
		applicablePaths.add(mustComeFromShopifyMatcher);
		Arrays.stream(maybeUris).forEach(i -> applicablePaths.add(new AntPathRequestMatcher(i)));
		
	}
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException { }
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		boolean mustBeFromShopify = false;
		boolean comesFromShopify = false;
		boolean isAlreadyAuthenticated = false;
		
		if(!applyFilter(request)) {
			chain.doFilter(request, response);
			
			return;
		}

		
		// this filter will be applied
		mustBeFromShopify = mustComeFromShopifyMatcher.matches((HttpServletRequest)request);

		comesFromShopify = isShopifyRequest(request);

		isAlreadyAuthenticated = isAlreadyAuthenticated();

		if(mustBeFromShopify) {

			if(comesFromShopify && hasValidNonce(request)) {
				// we don't need the ShopifyOriginToken if the path is to the uri Shopify is sending 
				// the authentication code to
				
			} else {
				// do not set any Authentication
				// the path must be .authenticated() 
				accessDeniedHandler.handle((HttpServletRequest)request, (HttpServletResponse)response, new AccessDeniedException("This request must come from Shopify"));
				return;
			}
			
		} else {
			if(comesFromShopify) {
				setEmbeddedApp((HttpServletRequest)request);
				if(!isAlreadyAuthenticated) {
					SecurityContextHolder.getContext().setAuthentication(new ShopifyOriginToken());
					
				}
			} else {
				if(!isAlreadyAuthenticated) {
					removeEmbeddedApp((HttpServletRequest)request);
				}
			}

		}
		
		chain.doFilter(request, response);

	}
	
	/*
	 * 
	 * Uses ShopifyVerificationStrategy to...
	 * 
	 * 1. Remove hmac parameter from query string
	 * 2. Build query string
	 * 3. HMAC-SHA256(query)
	 * 4. Is (3) = hmac value?
	 * 
	 */
	private boolean isShopifyRequest(ServletRequest request) {
		return shopifyVerificationStrategy.isShopifyRequest((HttpServletRequest)request);

	}
	
	private boolean hasValidNonce(ServletRequest request) {
		return shopifyVerificationStrategy.hasValidNonce((HttpServletRequest)request);

	}
	
	private boolean isAlreadyAuthenticated() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		
		if(auth instanceof OAuth2AuthenticationToken) {
			return true;
		}
		
		return false;

	}
	
	// should apply the filter if the request matches
	// any path passed in to this filter
	private boolean applyFilter(ServletRequest request) {
		HttpServletRequest req = (HttpServletRequest)request;
		
		boolean match = this.applicablePaths.stream().anyMatch(i -> i.matches(req));
		
		return match;
		
	}
	
	private void setEmbeddedApp(HttpServletRequest req) {
		HttpSession session = req.getSession(false);
		if(session != null) {
			session.setAttribute(SHOPIFY_EMBEDDED_APP, true);
		}
	}
	
	private void removeEmbeddedApp(HttpServletRequest req) {
		HttpSession session = req.getSession(false);
		if(session != null) {
			session.removeAttribute(SHOPIFY_EMBEDDED_APP);
		}
	}	
	public void setAccessDeniedHandler(AccessDeniedHandler handler) {
		this.accessDeniedHandler = handler;
	}

	@Override
	public void destroy() { }
	
}