package com.ppublica.shopify.security.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class DefaultUserInfoFilter implements Filter {
	
	/*
	 * 
	 * "info"
	 * 
	 * 



<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org" xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
<head lang="en">
</head>
<body>
<h1>Values for ShopifyApp [ProtectedResource]</h1>

<p>
apiKey: <span th:text='${#authentication.principal.attributes.get("shopify_client_api_key")}'>none found</span>
<br>
shopOrigin: <span th:text='${#authentication.principal.name}'>none found</span>
<br>
login for this session from embedded app?: <span th:text="${#session.getAttribute('SHOPIFY_EMBEDDED_APP') != null} ? ${#session.getAttribute('SHOPIFY_EMBEDDED_APP')} : 'false'">Unknown</span>
<br>
</p>

</body>
</html>


	 * 
	 * 
	 * 
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
