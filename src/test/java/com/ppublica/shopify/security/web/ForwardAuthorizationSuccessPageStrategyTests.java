package com.ppublica.shopify.security.web;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.security.core.Authentication;

public class ForwardAuthorizationSuccessPageStrategyTests {

	@Test
	public void handleAuthorizationPageWillForward() throws Exception {
		HttpServletRequest req = mock(HttpServletRequest.class);
		HttpServletResponse resp = mock(HttpServletResponse.class);
		Authentication auth = mock(Authentication.class);
		
		RequestDispatcher rd = mock(RequestDispatcher.class);
		doReturn(rd).when(req).getRequestDispatcher(ArgumentMatchers.any());
		
		ForwardAuthorizationSuccessPageStrategy str = new ForwardAuthorizationSuccessPageStrategy("/forwardUri");
		
		str.handleAuthorizationPage(req, resp, auth);
		
		verify(rd, times(1)).forward(req, resp);

		
	}
}