package com.ppublica.shopify.security.web;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A class that decorates the DefaultRedirectStrategy that ShopifyOAuth2AuthorizationRequestResolver invokes.
 * Instead of redirecting, it saves 2 authorization redirection URIs as request attributes. This allows for
 * "redirecting" from an iFrame when running in an embedded app.
 * 
 * @author N F
 * @see ShopifyOAuth2AuthorizationRequestResolver
 * @see DefaultRedirectStrategy
 */
public class ShopifyRedirectStrategy extends DefaultRedirectStrategy {
	public final String I_FRAME_REDIRECT_URI = "/oauth/authorize";
	private final String STATE = OAuth2ParameterNames.STATE;
	private final String SCOPE = OAuth2ParameterNames.SCOPE;
	private final String REDIRECT_URI = OAuth2ParameterNames.REDIRECT_URI;
	private final String CLIENT_ID = OAuth2ParameterNames.CLIENT_ID;
	private final String I_FRAME_AUTHENTICATION_URI_KEY = "I_FRAME_AUTHENTICATION_URI";
	private final String PARENT_AUTHENTICATION_URI_KEY = "PARENT_AUTHENTICATION_URI";
	

	/**
	 * Generates 2 authentication uris to authenticate with Shopify, as required. 
	 * These are saved as request attributes under "I_FRAME_AUTHENTICATION_URI" and "PARENT_AUTHENTICATION_URI".
	 * 
	 * @param request the HttpServletRequest where the uris will be saved
	 * @param authorizationRequest the OAuth2AuthorizationRequest that contains the authorizationUri
	 */
	public void saveRedirectAuthenticationUris(HttpServletRequest request, OAuth2AuthorizationRequest authorizationRequest) {
		
		// "template" already properly filled in with shop name
		String authorizationUri = authorizationRequest.getAuthorizationUri();

		String parentFrameRedirectUrl = super.calculateRedirectUrl(request.getContextPath(), authorizationUri);
		
		request.setAttribute(I_FRAME_AUTHENTICATION_URI_KEY, addRedirectParams(I_FRAME_REDIRECT_URI, authorizationRequest));
		request.setAttribute(PARENT_AUTHENTICATION_URI_KEY, addRedirectParams(parentFrameRedirectUrl, authorizationRequest));
		

	}
	
	
	/*
	 * Adds the following query parameters to the string:
	 * 
	 * 1. client_id
	 * 2. redirect_uri
	 * 3. scope
	 * 4. state
	 */
	private String addRedirectParams(String uri, OAuth2AuthorizationRequest authorizationRequest) {
		LinkedMultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
		queryParams.add(CLIENT_ID, authorizationRequest.getClientId());
		queryParams.add(REDIRECT_URI, authorizationRequest.getRedirectUri());
		queryParams.add(SCOPE, concatenateListIntoCommaString(new ArrayList<>(authorizationRequest.getScopes())));
		queryParams.add(STATE, authorizationRequest.getState());
		
		String re = UriComponentsBuilder
								.fromUriString(uri)
								.queryParams(queryParams)
								.build()
								.toString();
		
		return re;

	}
	
	/**
	 * Concatenates strings into one String, where each piece is separated by a ",".
	 * 
	 * For example, given a List that with elements "a", "b", and "c", this method will return "a,b,c".  
	 * 
	 * @param pieces the List&lt;String&gt; of pieces
	 * @return the pieces as a String
	 */
	public static String concatenateListIntoCommaString(List<String> pieces) {
		StringBuilder builder = new StringBuilder();
		
		if(pieces == null || pieces.size() < 1) {
			throw new RuntimeException("The provided List must contain at least one element");
		}
		pieces.stream()
					.forEach(e -> {
						builder.append(e);
						builder.append(",");
					});
		
		
		
		return builder.substring(0, builder.length() - 1);
	}

}
