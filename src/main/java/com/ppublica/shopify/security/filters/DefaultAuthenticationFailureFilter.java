package com.ppublica.shopify.security.filters;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/*
 * 
 * Whenever an error occurs during authentication, the user will be redirected to this uri.
 * 
 * It generates an HTML page for requests that match the path:
 * {authenticationFailurePath}
 * 
 */
public class DefaultAuthenticationFailureFilter implements Filter {
	
	private String authenticationFailurePath;
	
	public DefaultAuthenticationFailureFilter(String authenticationFailurePath) {
		this.authenticationFailurePath = authenticationFailurePath;
	}


	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		
		if(isAuthenticationFailureRequest(request)) {
			String bodyHtml = generateAuthorizationFailurePageHtml((HttpServletRequest)request);
			response.setContentType("text/html;charset=UTF-8");
			response.setContentLength(bodyHtml.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(bodyHtml);
			
			return;

		}
		
		chain.doFilter(request, response);
		
	}
	
	/*
	 * Returns:
	 * 
		<!DOCTYPE html>
		<head lang="en">
		  <meta charset="UTF-8"/>
  		  <title>Error!</title>
		</head>
		<body>
		  <div>
			<p>An error occurred during authentication.</p>
		  </div>
		</body>
		</html>
	 
	 *
	 */
	
	private String generateAuthorizationFailurePageHtml(HttpServletRequest req) {
		
		StringBuilder sb = new StringBuilder();
		
		sb.append("<!DOCTYPE html>\n"
				+ "  <head lang=\"en\">\n"
				+ "    <meta charset=\"UTF-8\">\n"
				+ "    <title>Error!</title>\n"
				+ "  </head>\n"
				+ "  <body>\n"
				+ "    <div>\n"
				+ "    <p>An error occurred during authentication.</p>\n"
				+ "    </div>\n"
				+ "  </body>\n"
				+ "</html>"
				);
		
		return sb.toString();
		
	}
	

	private boolean isAuthenticationFailureRequest(HttpServletRequest req) {
		if (!"GET".equals(req.getMethod())) {
			return false;
		}
		
		String uri = req.getRequestURI();
		
		int pathParamIndex = uri.indexOf(';');

		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}

		if ("".equals(req.getContextPath())) {
			return uri.equals(authenticationFailurePath);
		}

		return uri.equals(req.getContextPath() + authenticationFailurePath);
		
	}
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void destroy() {
		// TODO Auto-generated method stub
		
	}

}
