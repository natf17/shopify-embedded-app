package com.ppublica.shopify.security.authentication;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.util.UriUtils;

import com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;

/*
 * This class is invoked by ShopifyOriginFilter and UninstallFilter.
 * It uses ClientRegistrationRepository and ShopifyHttpSessionOAuth2AuthorizationRequestRepository.
 * 
 * This class ensures a request came from Shopify by checking for a valid HMAC parameter.
 * 
 * But for the "whitelisted redirection url", it is also necessary that it provide a nonce in the "state" parameter.
 * Since this is a redirection url, the OAuth2AuthorizationRequest should have already been saved in the HttpSession.
 * See ShopifyHttpSessionOAuth2AuthorizationRequestRepository.
 * 
 * This class also provides the logic to verify that an uninstall request came from Shopify by inspecting certain request headers.
 * 
 */
public class ShopifyVerificationStrategy {
	public static final String NONCE_PARAMETER = OAuth2ParameterNames.STATE;
	public static final String HMAC_PARAMETER = "hmac";
	public static final String HMAC_HEADER = "X-Shopify-Hmac-SHA256";

	
	private ShopifyHttpSessionOAuth2AuthorizationRequestRepository authReqRepository;
	private ClientRegistrationRepository clientRegistrationRepository;
	
	
	public ShopifyVerificationStrategy(ClientRegistrationRepository clientRegistrationRepository, ShopifyHttpSessionOAuth2AuthorizationRequestRepository authReqRepository) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authReqRepository = authReqRepository;

	}
	
	/*
	 * Perform HMAC verification as directed by Shopify:
	 * 
	 * 1. Obtains the hmac parameter from the query string
	 * 2. Obtains the client secret using the HttpServletRequest
	 * 3. Passes the query string, hmac, and secret to overloaded method.
	 * 
	 * This method checks in case the query string has been URL encoded
	 * 
	 * Tomcat by default decodes request parameters, so hmac is expected to be url decoded
	 */
	public boolean isShopifyRequest(HttpServletRequest request) {
		Map<String,String[]> requestParameters = this.getRequestParameters(request);
				
		if(requestParameters == null) {
			return false;
			
		}
		
		String[] hmacValues = requestParameters.get(HMAC_PARAMETER);
		
		if(hmacValues == null || hmacValues.length != 1) {
			return false;
		}
		
		String hmacValue = hmacValues[0];
		
		if(hmacValue.isEmpty()) {
			return false;
		}
		
		String secret = getClientSecret(request);
		
		if(!isShopifyQueryRequest(request.getQueryString(), hmacValue, secret)) {
			// try again...
			// sometimes the query string has been url encoded (by the server...?)
			return isShopifyQueryRequest(UriUtils.decode(request.getQueryString(), StandardCharsets.UTF_8), hmacValue, secret);

		}
		
		return true;

		

		
	}
	
	/*
	 * 1. Constructs the hmac parameter as it should appear in the url.
	 * 2. Removes it from the query string.
	 * 3. The query string is hashed with the secret.
	 * 4. If the hash equals the hmac value, the request came from Shopify.
	 */
	private boolean isShopifyQueryRequest(String rawQueryString, String hmac, String secret) {

		String hmacQueryStringPiece = HMAC_PARAMETER + "=" + hmac + "&";

		String processedQuery = rawQueryString.replaceFirst(Pattern.quote(hmacQueryStringPiece), "");
				
		if(rawQueryString.equals(processedQuery)) {
			// hmacQueryStringPiece not found
			// maybe the hmac parameter is the last parameter
			
			processedQuery = rawQueryString.replaceFirst(Pattern.quote("&" + HMAC_PARAMETER + "=" + hmac), "");

			if(rawQueryString.equals(processedQuery)) {
				// hmac not found 
				// it should have been found because the hmac parameter should be from query string
				// ... unless there is an encoding issue
				// (hmac as it appears in query string is encoded, whereas in parameter map it is decoded
				return false;

			}
			
		}
		
		String shaOfQuery = hash(secret, processedQuery);
		
		if(shaOfQuery.equals(hmac)) {
			return true;
		}

		return false;
		
	}

	
	/*
	 * This method makes sure there is an OAuth2AuthorizationRequest in the HttpSession
	 * that matches the nonce that was provided in this request.
	 * 
	 * This ensures that the nonce sent by the server (Shopify) matches the one 
	 * previously sent by the client (us)
	 * 
	 */
	
	public boolean hasValidNonce(HttpServletRequest request) {
		String nonce = request.getParameter(NONCE_PARAMETER);
		
		if(nonce == null || nonce.isEmpty()) {
			return false;
		}
		
		Map<String,OAuth2AuthorizationRequest> authorizationRequests = authReqRepository.getAuthorizationRequests(request);
		
		if(authorizationRequests != null) {
			if(authorizationRequests.keySet().contains(nonce)) {
				return true;
			}
			
			// try again...
			// Url-decode the nonce:
			nonce = UriUtils.decode(nonce, StandardCharsets.UTF_8);
			if(authorizationRequests.keySet().contains(nonce)) {
				return true;
			}
		}
	
		return false;
		
	}
	
	/*
	 * 
	 * This method uses the HttpServletRequest to obtain the client secret to use.
	 * 
	 * 
	 * Use the ShopifyHttpSessionOAuth2AuthorizationRequestRepository to get the OAuth2AuthorizationRequest 
	 * for this request.
	 * 
	 * Method 1: no OAuth2AuthorizationRequest
	 * 		- Use ShopifyHttpSessionOAuth2AuthorizationRequestRepository to extract the registrationId 
	 * 		  from the request path
	 * 		- Delegate to getClientSecretByRegistrationId(...) to search the ClientRegistrationRepository to get the 
	 * 		  ClientRegistration that matches the registrationId and obtain the client secret
	 * 
	 * Method 2: OAuth2AuthorizationRequest found
	 * 		- Obtain the clientId from the OAuth2AuthorizationRequest
	 * 		- Search the ClientRegistrationRepository to get the 
	 * 		  ClientRegistration that matches the clientId and obtain the client secret
	 * 
	 * 
	 * "/install/**": uses method 1 because no OAuth2AuthorizationRequest exists yet. 
	 * 				  (ShopifyOriginFilter is before OAuth2AuthorizationRequestRedirectFilter)
	 * 
	 * "/login/app/oauth2/code/**": uses method 2 because an OAuth2AuthorizationRequest has already been saved
	 * 
	 */
	
	public String getClientSecret(HttpServletRequest req) {
		
		OAuth2AuthorizationRequest authReq = authReqRepository.getAnAuthorizationRequest(req);
		String clientId = null;
		ClientRegistration reg = null;
		String clientSecret = null;
		

		if(authReq == null) {
			String registrationId = authReqRepository.extractRegistrationId(req);
			if(registrationId == null) {
				throw new RuntimeException("No registrationId found!");
			}
			
			clientSecret = getClientSecretByRegistrationId(registrationId);
			
		} else {
			clientId = authReq.getClientId();
			
			Iterator<ClientRegistration> it = ((InMemoryClientRegistrationRepository)clientRegistrationRepository).iterator();
			
			while(it.hasNext()) {
				ClientRegistration current = it.next();
				if(current.getClientId().equals(clientId)) {
					reg = current;
					break;
				}
			}
			
			if(reg == null) {
				throw new RuntimeException("No ClientRegistration found for " + clientId);
			}
			
			clientSecret = reg.getClientSecret();

		}
		
		if(clientSecret == null) {
			throw new RuntimeException("No client secret found");
		}
		
		return clientSecret;
		
	}
	
	/*
	 * Finds the client secret associated with the ClientRegistration with the given id by searching
	 * the ClientRegistrationRepository
	 */
	public String getClientSecretByRegistrationId(String registrationId) {
		ClientRegistration reg = clientRegistrationRepository.findByRegistrationId(registrationId);
		
		if(reg == null) {
			return null;
		}
		
		return reg.getClientSecret();
	}
	
	/*
	 * Allows swapping the request parameter map for unit tests 
	 */
	protected Map<String,String[]> getRequestParameters(HttpServletRequest req) {
		return req.getParameterMap();

	}
	
	/*
	 * Hashes the message using the secret
	 */
	public static String hash(String secret, String message) {
		
		String hash = null;
		
		try {
			
			Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		    SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
		    sha256_HMAC.init(secret_key);

		    hash = Hex.encodeHexString(sha256_HMAC.doFinal(message.getBytes("UTF-8")));
		    
		}
		    catch (Exception e){
		     throw new RuntimeException("Error hashing");
		}
		
		return hash;
	}
	
	/*
	 * Returns the body of HttpServletRequest as a String
	 */
	public String getBody(HttpServletRequest req) {
		InputStream in = null;
		 
		String body = null;
		try {
			in = req.getInputStream();
			IOUtils.toString(in, "UTF-8");
		} catch(IOException ex) {
			throw new RuntimeException("There was an error parsing the request body");
		}
		
		return body;
	}
	
	/*
	 * Uses a secret to hash the body.
	 * The result is then base64-encoded to compare to the base64-encoded hmac
	 */
	public boolean isShopifyHeaderRequest(String body, String hmac, String secret) {
		
		String hashValue = hash(secret, body);

		// From Shopify:
		// "Each webhook request includes a base64-encoded X-Shopify-Hmac-SHA256 header"
		
		String encodedValue = Base64.getEncoder().encodeToString(hashValue.getBytes());

		return encodedValue.equals(hmac);
	}
	
	/*
	 * Uninstalling the app (see UninstallFilter):
	 * 
	 * 	1. Makes sure the request has the X-Shopify-Hmac-SHA256 header
	 * 	2. Delegates to isShopifyHeaderRequest(...,...,...) to confirm the hash of the body
	 * 	   matches the hmac.
	 */
	public boolean isHeaderShopifyRequest(HttpServletRequest request, String registrationId) {
		String hmacValue = request.getHeader(HMAC_HEADER);
		
		if(hmacValue == null || hmacValue.isEmpty()) {
			return false;
		}
		
		String secret = getClientSecretByRegistrationId(registrationId);
		
		String body = getBody(request);
	
		return isShopifyHeaderRequest(body, hmacValue, secret);
	}
	

}