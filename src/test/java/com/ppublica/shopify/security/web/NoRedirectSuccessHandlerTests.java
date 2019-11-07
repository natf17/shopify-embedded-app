package com.ppublica.shopify.security.web;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

import org.mockito.ArgumentMatchers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.security.core.Authentication;


public class NoRedirectSuccessHandlerTests {
	
	@Test
	public void onAuthenticationSuccessWillAuthorizationPageInvokeStrategy() throws Exception {
		HttpServletRequest req = mock(HttpServletRequest.class);
		HttpServletResponse resp = mock(HttpServletResponse.class);
		Authentication auth = mock(Authentication.class);
		AuthorizationSuccessPageStrategy str = mock(AuthorizationSuccessPageStrategy.class);
		
		NoRedirectSuccessHandler handler = new NoRedirectSuccessHandler(str);
		
		handler.onAuthenticationSuccess(req, resp, auth);
		
		verify(resp, never()).sendRedirect(ArgumentMatchers.any());
		verify(str, times(1)).handleAuthorizationPage(req, resp, auth);;
		
	}

}
