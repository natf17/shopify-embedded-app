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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.util.UriUtils;

import com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;


/**
 * Provides methods for determining if a request came from Shopify. It needs access to 
 * ShopifyHttpSessionOAuth2AuthorizationRequestRepository to verify the nonce in the "state" request parameter for 
 * the "whitelisted redirection url". ClientRegistrationRepository is used to obtain the secret to check the HMAC.
 * 
 * 
 * @author N F
 * @see com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository
 * @see com.ppublica.shopify.security.filters.ShopifyOriginFilter
 * @see com.ppublica.shopify.security.filters.UninstallFilter
 */
public class ShopifyVerificationStrategy {
	private final Log logger = LogFactory.getLog(ShopifyVerificationStrategy.class);

	public static final String NONCE_PARAMETER = OAuth2ParameterNames.STATE;
	public static final String HMAC_PARAMETER = "hmac";
	public static final String HMAC_HEADER = "X-Shopify-Hmac-SHA256";

	
	private ShopifyHttpSessionOAuth2AuthorizationRequestRepository authReqRepository;
	private ClientRegistrationRepository clientRegistrationRepository;
	
	/**
	 * Create a new ShopifyVerificationStrategy
	 * 
	 * @param clientRegistrationRepository The ClientRegistrationRepository
	 * @param authReqRepository The ShopifyHttpSessionOAuth2AuthorizationRequestRepository
	 */
	public ShopifyVerificationStrategy(ClientRegistrationRepository clientRegistrationRepository, ShopifyHttpSessionOAuth2AuthorizationRequestRepository authReqRepository) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authReqRepository = authReqRepository;

	}
	
	
	/**
	 * Perform HMAC verification as directed by Shopify. It obtains the hmac parameter from the query string, and 
	 * the client secret to check the HMAC via the overloaded equivalent of this method.
	 * 
	 * <p>This method checks in case the query string has been URL encoded. Tomcat by default decodes request 
	 * parameters, so hmac is expected to be url decoded.</p>
	 * 
	 * @param request The HttpServletRequest
	 * @return true if HMAC is valid, false otherwise
	 */
	public boolean isShopifyRequest(HttpServletRequest request) {
		Map<String,String[]> requestParameters = this.getRequestParameters(request);
				
		if(requestParameters == null) {
			logger.debug("No request parameters found");
			return false;
			
		}
		
		String[] hmacValues = requestParameters.get(HMAC_PARAMETER);
		
		if(hmacValues == null || hmacValues.length != 1) {
			logger.debug("No HMAC parameter found");
			return false;
		}
		
		String hmacValue = hmacValues[0];
		
		if(hmacValue.isEmpty()) {
			logger.debug("HMAC parameter is empty");
			return false;
		}
		
		String secret = getClientSecret(request);
		
		if(!isShopifyQueryRequest(request.getQueryString(), hmacValue, secret)) {
			logger.debug("url-decoding request query string");
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
				logger.debug("HMAC parameter not found in query string");
				return false;

			}
			
		}
		
		String shaOfQuery = hash(secret, processedQuery);
		
		if(shaOfQuery.equals(hmac)) {
			return true;
		}

		return false;
		
	}

	
	/**
	 * This method makes sure there is an OAuth2AuthorizationRequest in the HttpSession
	 * that matches the nonce that was provided in this request.
	 * 
	 * This ensures that the nonce sent by the server (Shopify) matches the one 
	 * previously sent by the client (us).
	 * 
	 * @param request The HttpServletRequest
	 * @return true if the nonce is valid, false otherwise
	 */
	public boolean hasValidNonce(HttpServletRequest request) {
		String nonce = request.getParameter(NONCE_PARAMETER);
		
		if(nonce == null || nonce.isEmpty()) {
			logger.debug("No NONCE parameter found");
			return false;
		}
		
		Map<String,OAuth2AuthorizationRequest> authorizationRequests = authReqRepository.getAuthorizationRequests(request);
		
		if(authorizationRequests != null) {
			if(authorizationRequests.keySet().contains(nonce)) {
				return true;
			}
			
			// try again...
			// Url-decode the nonce:
			logger.debug("url-decoding nonce");
			nonce = UriUtils.decode(nonce, StandardCharsets.UTF_8);
			if(authorizationRequests.keySet().contains(nonce)) {
				return true;
			}
		}
	
		logger.debug("No matching OAuth2AuthorizationRequest found for the nonce");
		return false;
		
	}
	
	/**
	 * This method returns the client secret that matches this request. The client secret is obtained via 2 
	 * methods:
	 * 
	 * ShopifyHttpSessionOAuth2AuthorizationRequestRepository looks for a OAuth2AuthorizationRequest for the 
	 * current request. 
	 * 
	 * <p>Method 1: no OAuth2AuthorizationRequest</p>
	 * 	<ul>
	 * 		<li>Use ShopifyHttpSessionOAuth2AuthorizationRequestRepository to extract the registrationId from 
	 * 			the request path</li>
	 * 		<li>Delegate to getClientSecretByRegistrationId(...) to search the ClientRegistrationRepository to get the 
	 * 		  ClientRegistration that matches the registrationId and obtain the client secret</li>
	 * </ul>
	 * 
	 * <p>Method 2: OAuth2AuthorizationRequest found</p>
	 * 	<ul>
	 * 		<li>Obtain the clientId from the OAuth2AuthorizationRequest</li>
	 * 		<li>Search the ClientRegistrationRepository to get the ClientRegistration that matches the clientId
	 * 			 and obtain the client secret</li>
	 * 	</ul>
	 * 
	 * <p>Requests to the installation path (e.g. "/install/**") would use method 1 because no 
	 * OAuth2AuthorizationRequest exists yet. ShopifyOriginFilter is before 
	 * OAuth2AuthorizationRequestRedirectFilter. However, a request to the authorization redirect uri (e.g. 
	 * "/login/app/oauth2/code/**") would use method 2 because an OAuth2AuthorizationRequest has already been saved
	 * 
	 * @param req The HttpServletRequest
	 * @return The client secret
	 * @throws ShopifyVerificationException if client registration/secret not found
	 */
	public String getClientSecret(HttpServletRequest req) {
		
		OAuth2AuthorizationRequest authReq = authReqRepository.getAnAuthorizationRequest(req);
		String clientId = null;
		ClientRegistration reg = null;
		String clientSecret = null;
		

		if(authReq == null) {
			logger.debug("Installation request? Obtaining client secret using reg. id ");
			String registrationId = authReqRepository.extractRegistrationId(req);
			if(registrationId == null) {
				throw new ShopifyVerificationException("No registrationId found!");
			}
			
			clientSecret = getClientSecretByRegistrationId(registrationId);
			
		} else {
			logger.debug("Auth redirect request? Obtaining client secret from ClientRegistrationRepository");

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
				throw new ShopifyVerificationException("No ClientRegistration found for " + clientId);
			}
			
			clientSecret = reg.getClientSecret();

		}
		
		logger.debug("No client secret found");
		
		if(clientSecret == null) {
			throw new ShopifyVerificationException("No client secret found");
		}
		
		return clientSecret;
		
	}
	

	/**
	 * Finds the client secret associated with the ClientRegistration with the given id by searching
	 * the ClientRegistrationRepository.
	 * 
	 * @param registrationId The registration id
	 * @return The client secret, null if not found
	 */
	public String getClientSecretByRegistrationId(String registrationId) {
		ClientRegistration reg = clientRegistrationRepository.findByRegistrationId(registrationId);
		
		if(reg == null) {
			return null;
		}
		
		return reg.getClientSecret();
	}
	

	/**
	 * Obtain the request parameters from the HttpServletRequest object. Useful when swapping the request parameter 
	 * map for unit tests.
	 * 
	 * @param req The HttpServletRequest
	 * @return A map of parameters
	 */
	protected Map<String,String[]> getRequestParameters(HttpServletRequest req) {
		return req.getParameterMap();

	}
	
	
	/**
	 * Hashes the message using the secret.
	 * 
	 * @param secret The secret
	 * @param message The message
	 * @return The hashed message
	 * @throws ShopifyVerificationException if hashing error occurs
	 */
	public static String hash(String secret, String message) {
		
		String hash = null;
		
		try {
			
			Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		    SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
		    sha256_HMAC.init(secret_key);

		    hash = Hex.encodeHexString(sha256_HMAC.doFinal(message.getBytes("UTF-8")));
		    
		} catch (Exception e){
		    throw new ShopifyVerificationException("Error hashing");
		}
		
		return hash;
	}
	
	
	/**
	 * Read the body of the request and return as a String.
	 * 
	 * @param req The HttpServletRequest
	 * @return The body as a String
	 * @throws ShopifyVerificationException if error parsing body occurs
	 */
	public String getBody(HttpServletRequest req) {
		InputStream in = null;
		 
		String body = null;
		try {
			in = req.getInputStream();
			IOUtils.toString(in, "UTF-8");
		} catch(IOException ex) {
			throw new ShopifyVerificationException("There was an error parsing the request body");
		}
		
		return body;
	}
	
	
	/**
	 * Uses a secret to hash the body. The result is then base64-encoded to compare to the base64-encoded hmac.
	 * 
	 * @param body The request body
	 * @param hmac The hmac
	 * @param secret The secret
	 * @return true if the request has a valid hmac, false otherwise
	 */
	public boolean isShopifyHeaderRequest(String body, String hmac, String secret) {
		
		String hashValue = hash(secret, body);

		// From Shopify:
		// "Each webhook request includes a base64-encoded X-Shopify-Hmac-SHA256 header"
		
		String encodedValue = Base64.getEncoder().encodeToString(hashValue.getBytes());

		return encodedValue.equals(hmac);
	}
	
	
	/**
	 * Checks that the request has the  X-Shopify-Hmac-SHA256 header and a correct hmac in the body.
	 * This method is used when verifying a request to uninstall an app.
	 * 
	 * @param request The HttpServletRequest
	 * @param registrationId The registration id
	 * @return true if the hmac is valid, false otherwise
	 */
	public boolean isHeaderShopifyRequest(HttpServletRequest request, String registrationId) {
		String hmacValue = request.getHeader(HMAC_HEADER);
		
		if(hmacValue == null || hmacValue.isEmpty()) {
			logger.debug("No HMAC header found");
			return false;
		}
		
		String secret = getClientSecretByRegistrationId(registrationId);
		
		String body = getBody(request);
	
		return isShopifyHeaderRequest(body, hmacValue, secret);
	}
	

}