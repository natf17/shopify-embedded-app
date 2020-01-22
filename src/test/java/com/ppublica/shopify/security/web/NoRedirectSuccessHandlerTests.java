package com.ppublica.shopify.security.web;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

import org.mockito.ArgumentMatchers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.core.Authentication;


public class NoRedirectSuccessHandlerTests {
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(NoRedirectSuccessHandler.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	
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
