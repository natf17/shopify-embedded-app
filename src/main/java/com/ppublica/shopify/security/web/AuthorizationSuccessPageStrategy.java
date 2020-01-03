package com.ppublica.shopify.security.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 * A strategy that represents the behavior after successful authentication with Shopify.
 * 
 * @author N F
 * @see NoRedirectSuccessHandler
 *
 */
public interface AuthorizationSuccessPageStrategy {
	/**
	 * Determines how the authorization success page will be generated or found.
	 * 
	 * @param request The HttpServletRequest
	 * @param response The HttpServletResponse
	 * @param authentication The Authentication (OAuth2AuthenticationToken)
	 * @throws IOException When generating the response
	 * @throws ServletException When generating the response
	 */
	void handleAuthorizationPage(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException;

}
