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
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.csrf.CsrfToken;

/*
 * "selectStore"
 * 
 * This filter returns a default login page with a text box to log in to a particular store. The form will
 * trigger a GET request: {installPath}/shopify?shop={store_domain}
 * 
 * If the user is logged in already, a logout button will be shown instead, but only if the request didn't come
 * from an embedded app.
 * 
 */
public class DefaultLoginEndpointFilter implements Filter {
	
	private final String SHOPIFY_EMBEDDED_APP = ShopifyOriginFilter.SHOPIFY_EMBEDDED_APP;
	private String installPathShopify;
	private String logoutEndpoint;
	private String loginEnpoint;

	
	public DefaultLoginEndpointFilter(String loginEnpoint, String installPath, String logoutEndpoint) {
		this.installPathShopify = installPath + "/shopify";
		this.logoutEndpoint = logoutEndpoint;
		this.loginEnpoint = loginEnpoint;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		
		if(isLoginRequest(request)) {
			String bodyHtml = generateLoginPageHtml((HttpServletRequest)request);
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
		  <title>Please enter a store</title>
		</head>
		<body>
			<div">
			
			[-**-]
		
		  </div>
		</body>
		</html>
	 
	 *
	 */
	
	private String generateLoginPageHtml(HttpServletRequest req) {
		StringBuilder sb = new StringBuilder();
		
		sb.append("<!DOCTYPE html>\n"
				+ "<html lang=\"en\">\n"
				+ "  <head lang=\"en\">\n"
				+ "    <meta charset=\"UTF-8\">\n"
				+ "    <title>Please enter a store</title>\n"
				+ "  </head>\n"
				+ "  <body>\n"
				+ "    <div>\n"
				+        form(req)
				+ "    </div>\n"
				+ "  </body>\n"
				+ "</html>"
				);
		
		return sb.toString();
		
	}
		
	
	/*
	 * If not authenticated, returns:
	
		<form method="GET" action="/install/shopify"> 
	  	  Enter the store you wish to log in to:
			<p>
			<label for="store-domain">Store domain</label>
	        <input type="text" id="store-domain" name="shop">
	        </p>
		    <button type="submit">Sign in</button>
	    </form>
    
    
    
	 *
	 * If authenticated, returns:
	 * 

		You are already logged in.
		<form method="POST" action="/logout">
	        <input type="hidden" name="_csrf.parameterName" value="_csrf.token">
		    <button type="submit">Log out</button>
	    </form>
    
	 * The logout button is only included if it the request isn't from an embedded app.
	 */
	private String form(HttpServletRequest req) {
		String contextPath = req.getContextPath();

		CsrfToken csrfToken = (CsrfToken)req.getAttribute(CsrfToken.class.getName());
		
		StringBuilder sb = new StringBuilder();

		if(!isAuthenticated()) {
			sb.append("      <form method=\"GET\" action=\"" + contextPath + this.installPathShopify + "\">\n"
					+ "        Enter the store you wish to log in to:\n"
					+ "          <p>\n"
					+ "          <label for=\"store-domain\">Store domain</label>\n"
					+ "          <input type=\"text\" id=\"store-domain\" name=\"shop\">\n"
					+ "          </p>\n"
					+ "          <button type=\"submit\">Sign in</button>\n"
					+ "      </form>\n");
		} else {
			sb.append("      You are already logged in.\n");
			
			if(!isEmbeddedApp(req)) {
				sb.append("      <form method=\"POST\" action=\"" + contextPath + this.logoutEndpoint + "\">\n"
						+ "        <input type=\"hidden\" name=\"" + csrfToken.getParameterName() + "\" value=\""+ csrfToken.getToken() + "\">\n"
						+ "        <button type=\"submit\">Log out</button>\n"
						+ "      </form>\n");
			}
	
		}
		
		
		
		return sb.toString();
	}
	
	private boolean isAuthenticated() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		
		if(auth instanceof OAuth2AuthenticationToken) {
			return true;
		}
		
		return false;

	}
	
	private boolean isEmbeddedApp(HttpServletRequest req) {
		boolean isEmbedded = false;
		
		HttpSession session = req.getSession(false);
		if(session != null) {
			isEmbedded = session.getAttribute(SHOPIFY_EMBEDDED_APP) == null ? false : true;
		}
		
		return isEmbedded;
	}
	
	private boolean isLoginRequest(HttpServletRequest req) {
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
			return uri.equals(loginEnpoint);
		}

		return uri.equals(req.getContextPath() + loginEnpoint);
		
	}
	
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException { }

	@Override
	public void destroy() { }
	


}
