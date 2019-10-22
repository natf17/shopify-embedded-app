package com.ppublica.shopify.security.web;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;


import org.mockito.ArgumentMatchers;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.security.core.Authentication;


public class NoRedirectSuccessHandlerTests {
	
	@Test
	public void onAuthenticationSuccessWillForward() throws Exception {
		HttpServletRequest req = mock(HttpServletRequest.class);
		HttpServletResponse resp = mock(HttpServletResponse.class);
		Authentication auth = mock(Authentication.class);
		
		RequestDispatcher rd = mock(RequestDispatcher.class);
		
		doReturn(rd).when(req).getRequestDispatcher(ArgumentMatchers.any());
		
		NoRedirectSuccessHandler handler = new NoRedirectSuccessHandler("/login/app/oauth2/code");
		
		handler.onAuthenticationSuccess(req, resp, auth);
		
		verify(resp, never()).sendRedirect(ArgumentMatchers.any());
		verify(req, times(1)).getRequestDispatcher("/login/app/oauth2/code");
		verify(rd, times(1)).forward(req, resp);
		
	}

}
