package com.ppublica.shopify.security.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class DefaultInstallFilter implements Filter {
	
	/*
	 * "home"

<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org" xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
<head lang="en">
  <script src="https://cdn.shopify.com/s/assets/external/app.js"></script>
  
  
  <script th:inline="text">

  
  /*<![CDATA[*
		
  		var redirectFromParentPath = '[(${#request.getAttribute("PARENT_AUTHENTICATION_URI")})]';
		var redirectFromIFramePath = '[(${#request.getAttribute("I_FRAME_AUTHENTICATION_URI")})]';
		
		
		  
		  // If the current window is the 'parent', change the URL by setting location.href parentRedirectUri
		  if (window.top == window.self) {
			  console.log("In parent" + "url: " + redirectFromParentPath);
			  if(redirectFromParentPath){
				    window.location.assign(redirectFromParentPath);
			  }
		
		  // If the current window is the 'child', change the parent's URL with ShopifyApp.redirect
		  } else {
			  console.log("In child" + "url: " + redirectFromIFramePath);
			  // if there's no redirect, it's because the store has been installed, but it doesn't exist
			  // in the app database. Logging in from the browser will allow the app to store the token.
			  console.log("If you are seeing this, please login directly from your browser, not the embedded app.")
		    ShopifyApp.redirect(redirectFromIFramePath);
		  }
		  
	/*]]>*
		</script>
  
  
  
  <title>TEST</title>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
 
</head>
<body>
<div sec:authorize="!isAuthenticated()">
  There has been a problem logging in from the embedded app. Please log in directly from your browser.
  </div>
  
  <div sec:authorize="isAuthenticated()">	
	<h1>WELCOME</h1>
 	<a href="/info" >Protected resource</a>
  </div>



</body>
</html>

















	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
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
