package com.ppublica.shopify.security.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class DefaultAuthorizationRedirectPathFilter implements Filter {
	
	/*
	 * "success"
	 * 
	 * 

<!DOCTYPE html>
<html>
<body>
<p>INSTALLATION SUCCESS</p>
<a href="/info" >Protected resource</a>
</body>
</html>









	 */

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void destroy() {
		// TODO Auto-generated method stub
		
	}

}
