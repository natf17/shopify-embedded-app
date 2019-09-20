package com.lm.security.oauth2.integration.config;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/*
 * This post processor sets the scheme of the MockHttpServletRequest to "https". 
 */
public class HttpsRequestPostProcessor implements RequestPostProcessor {

	@Override
	public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
		request.setScheme("https");
		request.setServerPort(443);
		return request;
	}
	
	

}
