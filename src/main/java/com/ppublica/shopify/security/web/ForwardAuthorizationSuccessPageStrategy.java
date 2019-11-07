package com.ppublica.shopify.security.web;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;


public class ForwardAuthorizationSuccessPageStrategy implements AuthorizationSuccessPageStrategy {

	private String forwardUri;
	
	public ForwardAuthorizationSuccessPageStrategy(String forwardUri) {
		this.forwardUri = forwardUri;
	}
	@Override
	public void handleAuthorizationPage(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		RequestDispatcher rs = request.getRequestDispatcher(forwardUri);
		
		rs.forward(request, response);
		
	}

}
