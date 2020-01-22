package com.ppublica.shopify.security.web;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;


/**
 * An implementation of AuthorizationSuccessPageStrategy that forwards to the configured uri.
 * 
 * @author N F
 * @see com.ppublica.shopify.security.configuration.ShopifyPaths
 * @see com.ppublica.shopify.security.configuration.SecurityBeansConfig
 */
public class ForwardAuthorizationSuccessPageStrategy implements AuthorizationSuccessPageStrategy {
	private final Log logger = LogFactory.getLog(ForwardAuthorizationSuccessPageStrategy.class);

	private String forwardUri;
	
	public ForwardAuthorizationSuccessPageStrategy(String forwardUri) {
		this.forwardUri = forwardUri;
	}
	
	/**
	 * Forward to a uri.
	 * 
	 * @param request The HttpServletRequest
	 * @param response The HttpServletResponse
	 * @param authentication The Authentication (OAuth2AuthenticationToken)
	 * @throws IOException When forwarding
	 * @throws ServletException When forwarding
	 */
	@Override
	public void handleAuthorizationPage(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		RequestDispatcher rs = request.getRequestDispatcher(forwardUri);
		
		if(logger.isDebugEnabled()) {
			logger.info("Forwarding to " + forwardUri);
		}

		rs.forward(request, response);
		
	}

}
