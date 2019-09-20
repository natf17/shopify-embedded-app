package com.lm.security.filters;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;

import org.junit.Assert;
import org.junit.Test;

import com.ppublica.shopify.security.configuration.SecurityConfig;
import com.ppublica.shopify.security.filters.UninstallFilter;

public class UninstallFilterTest {
	
	/*
	 * When the uninstall url is hit, the UninstallFilter should be invoked
	 */
	@Test
	public void whenCalled_thenSuccessfulMatch() {
		String url = SecurityConfig.UNINSTALL_URI + "/shopify";
		
		UninstallFilter filter = new UninstallFilter(SecurityConfig.UNINSTALL_URI, null, null, null);
		
		HttpServletRequest req = mock(HttpServletRequest.class);
		when(req.getServletPath()).thenReturn("");
		when(req.getPathInfo()).thenReturn(url);
		
		Assert.assertTrue(filter.matches(req));
	}
	

}
