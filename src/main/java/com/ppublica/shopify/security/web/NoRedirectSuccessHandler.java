package com.ppublica.shopify.security.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/*
 * 
 * After successful authentication, the OAuth2LoginAuthenticationFilter will continue with the chain
 * and onto the landing page. This handler does nothing but delegate to SavedRequestAwareAuthenticationSuccessHandler,
 * which has been configured NOT TO REDIRECT.
 * 
 * 
 * After successful authentication, OAuth2LoginAuthenticationFilter will cede control to this success handler.
 * This handler 
 * 		- delegates to SavedRequestAwareAuthenticationSuccessHandler, which has been configured not to redirect
 * 		- has AuthorizationSuccessPageStrategy handle the page-generation or forward logic
 * 
 */
public class NoRedirectSuccessHandler implements AuthenticationSuccessHandler {
	
	private AuthorizationSuccessPageStrategy authPageStrategy;
	
	private SavedRequestAwareAuthenticationSuccessHandler defaultHandler;
	
	public NoRedirectSuccessHandler(AuthorizationSuccessPageStrategy authPageStrategy) {
		this.defaultHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		this.defaultHandler.setRedirectStrategy((i,j,k) -> { });
		this.authPageStrategy = authPageStrategy;
		
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		defaultHandler.onAuthenticationSuccess(request, response, authentication);
		authPageStrategy.handleAuthorizationPage(request, response, authentication);
	}

}
