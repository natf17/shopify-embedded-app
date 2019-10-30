package com.ppublica.shopify.security.filters;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

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
 * This filter generates an HTML page that is seen after successful completion of OAuth2 authorization with
 * Shopify.
 * 
 * Therefore, this filter is typically invoked after initial installation in the embedded app, or after
 * authenticating from outside the embedded app.
 * 
 * The current PROBLEM is that NoRedirectSuccessHandler forwards to the path, bypassing the filter
 * Possible solution: have the NoRedirectSuccessHandler write the response! But only if it's using the default.
 * If not, it should still forward, because the importing project would have provided a landing page.
 * 
 */
public class DefaultAuthorizationRedirectPathFilter implements Filter {
	
	Map<String, String> menuLinks;
	private String authorizationRedirectPath;
	
	public DefaultAuthorizationRedirectPathFilter(String authorizationRedirectPath, Map<String, String> menuLinks) {
		this.authorizationRedirectPath = authorizationRedirectPath;
		this.menuLinks = menuLinks;
	}
	


	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if(isAuthorizationRedirectRequest(request)) {

			String bodyHtml = generateAuthorizationRedirectPageHtml((HttpServletRequest)request);
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
  		  <title>Success!</title>
		</head>
		<body>
		  <div>
			<p>Authentication/installation SUCCESS!</p>
			
			[-**-]
			<a href="/info" >Protected resource</a>
		  </div>
		</body>
		</html>
	 
	 *
	 * The link is for every item in menuLinks
	 */
	
	private String generateAuthorizationRedirectPageHtml(HttpServletRequest req) {
		
		StringBuilder sb = new StringBuilder();
		
		sb.append("<!DOCTYPE html>\n"
				+ "  <head lang=\"en\">\n"
				+ "    <meta charset=\"UTF-8\">\n"
				+ "    <title>Success</title>\n"
				+ "  </head>\n"
				+ "  <body>\n"
				+ "    <div>\n"
				+ "    <p>Authentication/installation SUCCESS!</p>\n"
				+ 		generateMenuLinks()
				+ "    </div>\n"
				+ "  </body>\n"
				+ "</html>"
				);
		
		return sb.toString();
		
	}
	
	/*
	 * Returns:
	 * 

 		<a href="/info">Protected resource</a><br>
    
	 * 
	 * The link is for every item in menuLinks.
	 */
	private String generateMenuLinks() {
		StringBuilder sb = new StringBuilder();
		String link = null;
		String key = null;
		for(Map.Entry<String,String> menuEntry : menuLinks.entrySet()) {
			key = menuEntry.getKey();
			link = menuLinks.get(key);
			sb.append("      <a href=\"" + link + "\">" + menuEntry + "</a><br>\n");

		}
		
		return sb.toString();
	}
	
	/*
	 * should match any uri that begins with the authorizationRedirectPath
	 */
	private boolean isAuthorizationRedirectRequest(HttpServletRequest req) {
		if (!"GET".equals(req.getMethod())) {
			return false;
		}
		String uri = req.getRequestURI();
		
		int pathParamIndex = uri.indexOf(';');

		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}

		if (req.getQueryString() != null) {
			uri += "?" + req.getQueryString();
		}

		if ("".equals(req.getContextPath())) {
			return uri.startsWith(authorizationRedirectPath);
		}

		return uri.startsWith(req.getContextPath() + authorizationRedirectPath);
		
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
