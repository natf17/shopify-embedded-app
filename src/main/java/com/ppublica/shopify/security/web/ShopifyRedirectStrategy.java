package com.ppublica.shopify.security.web;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

/*
 * Decorates the default DefaultRedirectStrategy, and is invoked by ShopifyOAuth2AuthorizationRequestResolver.
 * 
 * Instead of redirecting, it saves 2 authorization redirection URIs as request attributes. This allows for
 * "redirecting" from an iFrame in an embedded app setting.
 */
public class ShopifyRedirectStrategy extends DefaultRedirectStrategy {
	public final String I_FRAME_REDIRECT_URI = "/oauth/authorize";
	private final String STATE = OAuth2ParameterNames.STATE;
	private final String SCOPE = OAuth2ParameterNames.SCOPE;
	private final String REDIRECT_URI = OAuth2ParameterNames.REDIRECT_URI;
	private final String CLIENT_ID = OAuth2ParameterNames.CLIENT_ID;
	private final String I_FRAME_AUTHENTICATION_URI_KEY = "I_FRAME_AUTHENTICATION_URI";
	private final String PARENT_AUTHENTICATION_URI_KEY = "PARENT_AUTHENTICATION_URI";
	

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
