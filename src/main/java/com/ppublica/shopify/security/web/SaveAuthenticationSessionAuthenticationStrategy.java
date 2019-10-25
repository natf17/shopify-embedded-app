package com.ppublica.shopify.security.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

/*
 * When setting continueChainBeforeSuccessfulAuthentication to true in 
 * OAuth2LoginAuthenticationFilter/AbstractAuthenticationProcessingFilter, the successfulAuthentication()
 * method is invoked AFTER continuing with the filter chain. However, this means that the Authentication
 * is also saved after invoking the rest of the filters, which means that an AnonymousAuthenticationToken
 * would still be the Authentication object when the request reacjes FilterSecurityInterceptor.
 * 
 * We need to save the Authentication BEFORE continuing, and this SessionAuthenticationStrategy 
 * implementation does that.
 * 
 * Publishing an authentication success event and invoking rememberMeServices is still done after processing
 * the filter chain.
 */
public class SaveAuthenticationSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) throws SessionAuthenticationException {
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
	}

}
