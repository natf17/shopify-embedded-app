package com.ppublica.shopify.security.web;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/*
 * This class replaces the default HttpSessionOAuth2AuthorizationRequestRepository that's invoked by:
 * 	- ShopifyOAuth2AuthorizationRequestResolver: to save the OAuth2AuthorizationRequest
 * 	- ShopifyVerificationStrategy to extract the current OAuth2AuthorizationRequest
 * 
 * Why the need to replace the default?
 * 
 * In ShopifyOAuth2AuthorizationRequestResolver, when we call the saveAuthorizationRequest() method, we don't
 * have an HttpServletResponse. This class is functionally identical to the default, but with a different method signature.
 * The OAuth2AuthorizationRequest is saved in the session as a Map<String, OAuth2AuthorizationRequest>.
 * 
 * In ShopifyVerificationStrategy, obtaining the client secret requires obtaining the saved OAuth2AuthorizationRequest,
 * or sometimes might require extracting the registration id from the request path to search for the ClientRegistration
 * (and then obtain the client secret).
 */
public class ShopifyHttpSessionOAuth2AuthorizationRequestRepository {
	public static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME =
			HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";
	
	private AntPathRequestMatcher installPathRequestMatcher;

	public ShopifyHttpSessionOAuth2AuthorizationRequestRepository(String installPath) {
		this.installPathRequestMatcher = new AntPathRequestMatcher(
				installPath + "/{registrationId}");
	}
	
	@SuppressWarnings("unchecked")
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request) {
		String state = authorizationRequest.getState();
		
		HttpSession session = request.getSession(false);
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = session == null ? null :
				(Map<String, OAuth2AuthorizationRequest>) session.getAttribute(DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME);
		
		if (authorizationRequests == null) {
			authorizationRequests =  new HashMap<>();
		}		
		
		authorizationRequests.put(state, authorizationRequest);

		request.getSession().setAttribute(DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequests);

	}
	
	
	@SuppressWarnings("unchecked")
	public Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = session == null ? null :
				(Map<String, OAuth2AuthorizationRequest>) session.getAttribute(DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME);
		if (authorizationRequests == null) {
			return new HashMap<>();
		}
		return authorizationRequests;
	}
	
	public Map.Entry<String, OAuth2AuthorizationRequest> getFirstAuthorizationRequest(HttpServletRequest request) {
		
		Map<String, OAuth2AuthorizationRequest> reqs = this.getAuthorizationRequests(request);
				
		if(reqs.size() < 1) {
			return null;
		}
		
		for(Map.Entry<String, OAuth2AuthorizationRequest> authReqEntry : reqs.entrySet()) {
			if(authReqEntry.getValue() != null) {
				return authReqEntry;
			}
	
		}
		
		return null;
		
		
	}
	
	// Used by ShopifyVerificationStrategy when the request matches authorization uri/install path
	// provided to ShopifyOAuth2AuthorizationRequestResolver
	public String extractRegistrationId(HttpServletRequest request) {
		
		String registrationId;
		
		if (this.installPathRequestMatcher.matches(request)) {
			registrationId = this.installPathRequestMatcher
					.extractUriTemplateVariables(request).get("registrationId");
		} else {
			registrationId = null;
		}

		return registrationId;
	}
	
	
}
