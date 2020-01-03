package com.ppublica.shopify.security.web;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * 
 * A "pseudo-implementation" of AuthorizationRequestRepository that stores OAuth2AuthorizationRequest in the
 * HttpSession. 
 * 
 * <p>This class replaces the default HttpSessionOAuth2AuthorizationRequestRepository that's used by:</p>
 * <ul>
 * 	<li>ShopifyOAuth2AuthorizationRequestResolver: to save the OAuth2AuthorizationRequest</li>
 * 	<li>ShopifyVerificationStrategy to extract the current OAuth2AuthorizationRequest</li>
 * </ul>
 * 
 * <p>Why the need to replace the default?</p>
 * 
 * <p>In ShopifyOAuth2AuthorizationRequestResolver, when we call the saveAuthorizationRequest() method, we don't
 * have an HttpServletResponse. This class is functionally identical to the default, but with a different method
 * signature. The OAuth2AuthorizationRequest is saved in the session as a Map&lt;String, OAuth2AuthorizationRequest&gt;.</p>
 * 
 * <p>In ShopifyVerificationStrategy, obtaining the client secret requires obtaining the saved OAuth2AuthorizationRequest,
 * or sometimes might require extracting the registration id from the request path to search for the ClientRegistration
 * (and then obtain the client secret).</p>
 * 
 * @see ShopifyOAuth2AuthorizationRequestResolver
 * @see com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy
 */
public class ShopifyHttpSessionOAuth2AuthorizationRequestRepository {
	public static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME =
			HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";
	
	public static final String REGISTRATION_ID_URI_VARIABLE_NAME = ShopifyOAuth2AuthorizationRequestResolver.REGISTRATION_ID_URI_VARIABLE_NAME;
	private AntPathRequestMatcher installPathRequestMatcher;

	public ShopifyHttpSessionOAuth2AuthorizationRequestRepository(String installPath) {
		this.installPathRequestMatcher = new AntPathRequestMatcher(
				installPath + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
	}
	
	/**
	 * Save the OAuth2AuthorizationRequest in HttpSession.
	 * 
	 * @param authorizationRequest the OAuth2AuthorizationRequest to be persisted
	 * @param request the HttpServletRequest from which to extract HttpSession
	 */
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
	
	/**
	 * Looks for all OAuth2AuthorizationRequest in the request's session.
	 * 
	 * @param request the current HttpSevletRequest
	 * @return a Map of OAuth2AuthorizationRequest with their corresponding state
	 */
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
	
	/**
	 * Get one and only one OAuth2AuthorizationRequest from the session. Used in cases where no other 
	 * OAuth2AuthorizationRequest exists.
	 * 
	 * @param request the current HttpServletRequest
	 * @return the first OAuth2AuthorizationRequest
	 */
	public OAuth2AuthorizationRequest getAnAuthorizationRequest(HttpServletRequest request) {
		
		Map<String, OAuth2AuthorizationRequest> reqs = this.getAuthorizationRequests(request);
				
		if(reqs.size() < 1) {
			return null;
		}
		
		for(Map.Entry<String, OAuth2AuthorizationRequest> authReqEntry : reqs.entrySet()) {
			if(authReqEntry.getValue() != null) {
				return authReqEntry.getValue();
			}
	
		}
		
		return null;
		
		
	}
	/**
	 * Extract the registration id from the request path. Used by ShopifyVerificationStrategy when the request
	 * matches the install path
	 * 
	 * @param request the current HttpServletRequest
	 * @return the registration id
	 */
	public String extractRegistrationId(HttpServletRequest request) {
		
		String registrationId;
		
		if (this.installPathRequestMatcher.matches(request)) {
			registrationId = this.installPathRequestMatcher.matcher(request).getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME);
		} else {
			registrationId = null;
		}

		return registrationId;
	}
	
	
}
