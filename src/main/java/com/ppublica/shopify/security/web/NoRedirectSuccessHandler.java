package com.ppublica.shopify.security.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;


/**
 * This handler prevents redirection after successful authentication, and instead calls the default
 * AuthorizationSuccessPageStrategy.
 * 
 * @author N F
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
