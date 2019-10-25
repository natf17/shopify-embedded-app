package com.ppublica.shopify.security.web;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/*
 * The NoRedirectSuccessHandler is invoked by OAuth2LoginAuthenticationFilter upon successful authentication.
 * 
 * This success handler decorates the default SavedRequestAwareAuthenticationSuccessHandler
 * so that it will perform as intended, but without the redirect support (we can't redirect in an embedded app).
 * Thus, the DefaultRedirectStrategy is replaced with an empty implementation.
 * 
 * Afterwards, however, it will forward to the the "authentication url" resource.
 * By default, the Spring Security filter chain will not be triggered for the forward.
 * 
 * 
 * UPDATE: since the OAuth2LoginAuthenticationFilter will continue with the chain after successful authentication,
 * and onto the landing page, this handler does nothing.
 * 
 */
public class NoRedirectSuccessHandler implements AuthenticationSuccessHandler {
	
	private SavedRequestAwareAuthenticationSuccessHandler defaultHandler;
	private String authorizationRedirectPath;
	
	public NoRedirectSuccessHandler(String authorizationRedirectPath) {
		this.defaultHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		this.defaultHandler.setRedirectStrategy((i,j,k) -> { });
		this.authorizationRedirectPath = authorizationRedirectPath;
		
		
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		defaultHandler.onAuthenticationSuccess(request, response, authentication);
		//RequestDispatcher rs = request.getRequestDispatcher(authorizationRedirectPath);

		//rs.forward(request, response);
		
	}

}
