package com.ppublica.shopify.security.web;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;

import com.ppublica.shopify.security.service.TokenService;

/**
 * ShopifyOAuth2AuthorizationRequestResolver is similar to DefaultOAuth2AuthorizationRequestResolver.
 * It's called by OAuth2AuthorizationRequestRedirectFilter to save the OAuth2AuthorizationRequest
 * when the app is being installed (embedded app) or if the user wants to log in (directly from the browser).
 *
 * <p>Unlike DefaultOAuth2AuthorizationRequestResolver, we don't want to redirect when the user isn't authenticated.
 * We want the redirection to happen in a page returned to the browser. This implementation of 
 * OAuth2AuthorizationRequestResolver accounts for that use case. </p>
 *     
 * @see org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver
 * 
 */
public class ShopifyOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
	/**
	 * The key to store the shop name as an additional parameter in OAuth2AuthorizationRequest.
	 * It must match the template variable in ClientRegistration token_uri
	 */
	public static final String SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN = "shop";
	
	/**
	 * The uri path variable that corresponds to the registration id.
	 */
	public static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
	
	
	private ClientRegistrationRepository clientRegistrationRepository;
	private AntPathRequestMatcher installPathRequestMatcher;
	private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private final ShopifyRedirectStrategy authorizationRedirectStrategy = new ShopifyRedirectStrategy();
	private final ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository;
	private final String loginUri;

	
	/**
	 * Build a ShopifyOAuth2AuthorizationRequestResolver
	 * 
	 * @param clientRegistrationRepository where to look for a ClientRegistation
	 * @param customAuthorizationRequestRepository to save OAuth2AuthorizationRequest
	 * @param installPathBaseUri the path to the install page (defaults to "/install")
	 * @param loginUri the path to redirect to for login outside of an embedded app
	 */
	public ShopifyOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, 
							ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository,
							String installPathBaseUri, String loginUri) {

		this.clientRegistrationRepository = clientRegistrationRepository;
		this.customAuthorizationRequestRepository = customAuthorizationRequestRepository;
		this.installPathRequestMatcher = new AntPathRequestMatcher(
				installPathBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME+ "}");
		this.loginUri = loginUri;
	}
	

	/**
	 * Prepare the request to authenticate with Shopify. By default, this class will match any request that matches
	 * "/install/shopify" and is not authenticated with an OAuth2AuthenticationToken.
	 * 
	 * <p>Instead of immediately redirecting the user to log in, this method returns null to continue with the FilterChain.
	 * Redirection will only happen when there's no shop parameter provided. An implicit OAuth2AuthorizationRequest
	 * is returned so that the filter will handle the redirect. Since it's implicit, it will not be saved by the filter.</p>
	 * 
	 * This resolver... 
	 * <pre>
	 * 1. Looks for a ClientRegistration that matches "/install/shopify".
	 * 2. Creates an OAuth2AuthorizationRequest:
	 *  	- clientId: from ClientRegistration
	 *  	- authorizationUri: uses the "shop" parameter in the request to populate the uri template variable in 
	 *  	  the authorizationUri stored in the ProviderDetails in the ClientRegistration
	 *  	  (default: "https://{shop}/admin/oauth/authorize")
	 *  	- redirectUri: expands and populates the uri template in ClientRegistration
	 *  	  (default: "{baseUrl}/login/app/oauth2/code/shopify")
	 *  	- scopes: from ClientRegistration
	 *  	- state: generated by Base64StringKeyGenerator
	 *  	- attributes: contains the registrationId (e.g. "shopify")
	 *  	- additionalParameters: contains the shop name
	 * 3. Uses the custom ShopifyHttpSessionOAuth2AuthorizationRequestRepository to save the OAuth2AuthorizationRequest
	 *     in the HttpSession.
	 * 4. Delegates to ShopifyRedirectStrategy to set 2 request attributes that contain the 2 authorizationUris
	 *     that the Shopify-provided Javascript needs to redirect: one for redirecting from the "parent window" and
	 *     another for redirecting from an iFrame.
	 * </pre>
	 * 
	 * @param request the current request
	 * @return null if authenticated, or if shop name is provided as a parameter
	 * @return OAuth2AuthorizationRequest to redirect if shop parameter isn't provided in unauthenticated request
	 * @see ShopifyHttpSessionOAuth2AuthorizationRequestRepository
	 * @see ShopifyRedirectStrategy
	 */
	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		// is already properly authenticated, skip
		if(isAuthenticated(request)) {
			return null;
		}
		// extract the registrationId (ex: "shopify")
		String registrationId;
		
		if (this.installPathRequestMatcher.matches(request)) {
			registrationId = this.installPathRequestMatcher
					.matcher(request).getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME);

			if(registrationId == null || registrationId.isEmpty()) {

				throw new IllegalArgumentException("Invalid registration id");
			}
		} else {
			return null;

		}

		// At this point, either the request came from Shopify, or make sure shop param was provided
		String shopName = null;
		
		shopName = this.getShopName(request);
		
		if(shopName == null || shopName.isEmpty() || registrationId == null) {
			// shop name is required, or registrationId
			// trigger a redirect
			return redirectToLogin();
		}
		
		// obtain a ClientRegistration for extracted registrationId
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			throw new IllegalArgumentException("Invalid Client Registration: " + registrationId);
		}
		
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());

		// only the Authorization code grant is accepted
		OAuth2AuthorizationRequest.Builder builder;
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			builder = OAuth2AuthorizationRequest.authorizationCode();
		} else {
			throw new IllegalArgumentException("Invalid Authorization Grant Type ("  +
					clientRegistration.getAuthorizationGrantType().getValue() +
					") for Client Registration: " + clientRegistration.getRegistrationId());
		}
		
		String redirectUriStr = this.expandRedirectUri(request, clientRegistration);
		
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN, shopName);
		
		OAuth2AuthorizationRequest authorizationRequest = builder
				.clientId(clientRegistration.getClientId())
				.authorizationUri(this.generateAuthorizationUri(request, clientRegistration.getProviderDetails().getAuthorizationUri()))
				.redirectUri(redirectUriStr)
				.scopes(clientRegistration.getScopes())
				.state(this.stateGenerator.generateKey())
				.attributes(attributes)
				.additionalParameters(additionalParameters)
				.build();


		// Save the OAuth2AuthorizationRequest
		customAuthorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request);

		// DO NOT redirect, build redirecturi: DefaultRedirectStrategy		
		authorizationRedirectStrategy.saveRedirectAuthenticationUris(request, authorizationRequest);
		
		return null;
	}

	
	
	/**
	 * Method called to handle a ClientAuthorizationRequiredException. OAuth2RequestRedirectFilter calls
	 * this method to create a redirect uri to the authorization server. This scenario should never occur, 
	 * so it always returns null.
	 * 
	 * @return null
	 */
	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest req, String registrationId) {

		return null;
	}
 
	
	private String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration) {
		// Supported URI variables -> baseUrl, registrationId
		// EX: "{baseUrl}/oauth2/code/{registrationId}"
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());
		String baseUrl = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replaceQuery(null)
				.replacePath(request.getContextPath())
				.build()
				.toUriString();
		uriVariables.put("baseUrl", baseUrl);

		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
				.buildAndExpand(uriVariables)
				.toUriString();
	}
	

	// Expects a shop request parameter to generate the authorization uri
	private String generateAuthorizationUri(HttpServletRequest request, String authorizationUriTemplate) {
		String shopName = this.getShopName(request);
		
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put(SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN, shopName);
		
		String authorizationUri = UriComponentsBuilder
							.fromHttpUrl(authorizationUriTemplate)
							.buildAndExpand(uriVariables)
							.toUriString();

		return authorizationUri;
	}
	
	private String getShopName(HttpServletRequest request) {
		String shopName = request.getParameter(TokenService.SHOP_ATTRIBUTE_NAME);
		
		if(shopName == null || shopName.isEmpty()) {
			return null;
		}
		
		return shopName;
	}
	
	private boolean isAuthenticated(HttpServletRequest request) {
		if(SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2AuthenticationToken) {
			return true;
		}
		
		return false;
	}
	
	// return an OAuth2AuthorizationRequest so OAuth2AuthorizationRequestRedirectFilter
	// will redirect
	private OAuth2AuthorizationRequest redirectToLogin() {
		// clear all authentication
		if(SecurityContextHolder.getContext().getAuthentication() != null) {
			SecurityContextHolder.getContext().setAuthentication(null);
		}
		
		
		// The grant type cannot be AUTHORIZATION_CODE, since we don't want the 
		// OAuth2AuthorizationRequest saved in the session just yet
		OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.implicit()
				.authorizationUri("REDIRECT")
				.authorizationRequestUri(this.loginUri) // the redirect uri
				.clientId("REDIRECT")
				.redirectUri("REDIRECT")
				.build();

		return request;
				
				
	}
	

}
