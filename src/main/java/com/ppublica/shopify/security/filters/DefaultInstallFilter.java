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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

/**
 * A filter that generates an HTML page with all the installation logic Shopify requires for an embedded app.
 * It uses 2 request attributes (set by ShopifyRedirectStrategy) to populate 2 redirect uris. Which one is used
 * is determined via Javascript - it'll determine if it is being rendered in an embedded app or not.
 * 
 * <p>Paths to {installPath}/shopify will match this filter.</p>
 * 
 * @author N F
 * @see com.ppublica.shopify.security.configuration.ShopifyPaths
 * @see com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer
 * @see com.ppublica.shopify.security.web.ShopifyRedirectStrategy
 */
public class DefaultInstallFilter implements Filter {
	private final Log logger = LogFactory.getLog(DefaultInstallFilter.class);
	
	public static String PARENT_AUTHENTICATION_URI = "PARENT_AUTHENTICATION_URI";
	
	public static String I_FRAME_AUTHENTICATION_URI = "I_FRAME_AUTHENTICATION_URI";
	
	private Map<String, String> menuLinks;
	
	private String installPathShopify;

	/**
	 * Construct a DefaultInstallFilter
	 * 
	 * @param installPath The install path, not ending in "/shopify"
	 * @param menuLinks The links to display if this page is accessed while authenticated
	 */
	public DefaultInstallFilter(String installPath, Map<String, String> menuLinks) {
		this.installPathShopify = installPath + "/shopify";
		this.menuLinks = menuLinks;
	}
	
	
	
	/**
	 * Generate the install page HTML. It will force a redirect to Shopify to initiate the OAuth authorization 
	 * flow if the request is not authenticated. If the request is authenticated, a series of links are displayed 
	 * as provided in Map&lt;String, String&gt;menuLinks.
	 * 
	 * @param req The request
	 * @param res The response
	 * @param chain The security filter chain	
	 * @throws IOException If unable to write request
	 * @throws ServletException When invoking the chain
	 */
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		
		if(isInstallRequest(request)) {
			logger.info("Generating default installation page");
			
			String bodyHtml = generateInstallPageHtml((HttpServletRequest)request);
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
		  <script src="https://cdn.shopify.com/s/assets/external/app.js"></script>
		  <script>
  			var redirectFromParentPath = '[(${#request.getAttribute("PARENT_AUTHENTICATION_URI")})]';
			var redirectFromIFramePath = '[(${#request.getAttribute("I_FRAME_AUTHENTICATION_URI")})]';
			// If the current window is the 'parent', change the URL by setting location.href parentRedirectUri
			if (window.top == window.self) {
				console.log("In parent: " + redirectFromParentPath);
				if(redirectFromParentPath){
					window.location.assign(redirectFromParentPath);
				}
		  	} else {
		  		// If the current window is the 'child', change the parent's URL with ShopifyApp.redirect
				console.log("In child: " + redirectFromIFramePath);
			  	// if there's no redirect, it's because the store has been installed, but it doesn't exist
			  	// in the app database. Logging in from the browser will allow the app to store the token.
			  	console.log("If you are seeing this, please log in directly from your browser, not the embedded app.")
		    	ShopifyApp.redirect(redirectFromIFramePath);
		  	}
		  </script>
  		  <title>TEST</title>
		</head>
		<body>
		  <div>
			
			[-**-]
		
		  </div>
		</body>
		</html>
	 
	 *
	 */
	
	private String generateInstallPageHtml(HttpServletRequest req) {
		
		String parentAuthenticationUri = (String)req.getAttribute("PARENT_AUTHENTICATION_URI");
		String parentString = parentAuthenticationUri != null ? ("'" + parentAuthenticationUri + "'") : parentAuthenticationUri;
		String iFrameAuthenticationUri = (String)req.getAttribute("I_FRAME_AUTHENTICATION_URI");
		String iFrameString = iFrameAuthenticationUri != null ? ("'" + iFrameAuthenticationUri + "'") : iFrameAuthenticationUri;

		StringBuilder sb = new StringBuilder();
		
		sb.append("<!DOCTYPE html>\n"
				+ "  <head lang=\"en\">\n"
				+ "    <meta charset=\"UTF-8\">\n"
				+ "    <script src=\"https://cdn.shopify.com/s/assets/external/app.js\"></script>\n"
				+ "    <script>\n"
				+ "    	var redirectFromParentPath = " +  parentString + ";\n"
				+ "    	var redirectFromIFramePath = " + iFrameString + ";\n"
				+ "    	// If the current window is the 'parent', change the URL by setting location.href parentRedirectUri\n"
				+ "    	if (window.top == window.self) {\n"
				+ "    		console.log(\"In parent: \" + redirectFromParentPath);\n"
				+ "    		if(redirectFromParentPath){\n"
				+ "    			window.location.assign(redirectFromParentPath);\n"
				+ "    		}\n"
				+ "    	} else {\n"
				+ "    		// If the current window is the 'child', change the parent's URL with ShopifyApp.redirect\n"
				+ "    		console.log(\"In child: \" + redirectFromIFramePath);\n"
				+ "    		// if there's no redirect, it's because the store has been installed, but it doesn't exist\n"
				+ "    		// in the app database. Logging in from the browser will allow the app to store the token.\n"
				+ "    		console.log(\"If you are seeing this, please log in directly from your browser, not the embedded app.\")\n"
				+ "    		ShopifyApp.redirect(redirectFromIFramePath);\n"
				+ "    	}\n"
				+ "    </script>"
				+ "    <title>TEST</title>\n"
				+ "  </head>\n"
				+ "  <body>\n"
				+ "    <div>\n"
				+        generateBody(req)
				+ "    </div>\n"
				+ "  </body>\n"
				+ "</html>"
				);
		
		return sb.toString();
		
	}
	
	
	/*
	 * If not authenticated, returns:
	 * 

  		There has been a problem logging in from the embedded app. Please log in directly from your browser.
    
    
	 *
	 * If authenticated, returns:
	 * 

		<h1>WELCOME</h1>
 		<a href="/info">Protected resource</a><br>
    
	 * 
	 * The link is for every item in menuLinks
	 */
	private String generateBody(HttpServletRequest req) {
		StringBuilder sb = new StringBuilder();

		if(!isAuthenticated()) {
			sb.append("      There has been a problem logging in from the embedded app. Please log in directly from your browser.\n");
		} else {
			sb.append("      <h1>WELCOME</h1>\n");
			String link = null;
			String key = null;
			for(Map.Entry<String,String> menuEntry : menuLinks.entrySet()) {
				key = menuEntry.getKey();
				link = menuLinks.get(key);
				sb.append("      <a href=\"" + link + "\">" + menuEntry + "</a><br>\n");

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
	
	private boolean isInstallRequest(HttpServletRequest req) {
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
			return uri.equals(installPathShopify);
		}

		return uri.equals(req.getContextPath() + installPathShopify);
		
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
