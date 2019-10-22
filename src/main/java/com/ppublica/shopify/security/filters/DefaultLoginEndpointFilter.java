package com.ppublica.shopify.security.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class DefaultLoginEndpointFilter implements Filter {

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
	
	/*
	 * "selectStore"
	 * 
	 * 
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org" xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
<head lang="en">
  
  <title>ENTER A STORE</title>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
  
	
 
</head>
<body>
<h1>Hello</h1>
 
   <div sec:authorize="!isAuthenticated()">
  Enter the store you wish to log in to.
  <form th:action="@{/install/shopify}" method="GET" enctype="application/x-www-form-urlencoded" id="select-store-form"> 
        <input id="select-store_name" type="text" name="shop">
      	<input type="submit">
    </form>
  </div>
  
  <div sec:authorize="isAuthenticated()">
  You are already logged in.
  
	<form th:if="${session.SHOPIFY_EMBEDDED_APP} != true" name="logout" action="/logout" method="POST">
	<input type="hidden"  th:name="${_csrf.parameterName}"   th:value="${_csrf.token}"/>
	<button type="submit">Log out</button>
	</form>
  </div>
</body>
</html>

	 
	 *
	 */

}
