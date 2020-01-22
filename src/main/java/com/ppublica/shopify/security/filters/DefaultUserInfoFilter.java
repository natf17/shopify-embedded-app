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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;


/**
 * This filter responds to the userInfoPath it's provided and displays some useful information about the app:
 * <ul>
 * <li>apiKey: the api key for the app</li>
 * <li>shopOrigin: the domain of the store that's currently logged in</li>
 * <li>whether the initial login for the session was done from within an embedded app</li>
 * </ul>
 * If the request isn't authenticated, the request passes to the next filter.
 * 
 * @author N F
 * @see com.ppublica.shopify.security.configuration.ShopifyPaths
 * @see com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer
 */
public class DefaultUserInfoFilter implements Filter {
	private final Log logger = LogFactory.getLog(DefaultUserInfoFilter.class);
	
	private String userInfoPathShopify;

	/**
	 * Construct a DefaultUserInfoFilter
	 * 
	 * @param userInfoPathShopify The path to access the info page
	 */
	public DefaultUserInfoFilter(String userInfoPathShopify) {
		this.userInfoPathShopify = userInfoPathShopify;
	}
	

	/**
	 * If the request matches this filter and is authenticated, produce an info page.
	 * 
	 * @param request The request
	 * @param response The response
	 * @param chain The security filter chain
	 * 
	 * @throws IOException If unable to write request
	 * @throws ServletException When invoking the chain
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse resp = (HttpServletResponse) response;
		
		if(isUserInfoRequest(req) && isAuthenticated()) {
			logger.info("Generating default info page");
			String bodyHtml = generateUserInfoPageHtml((HttpServletRequest)request);
			resp.setContentType("text/html;charset=UTF-8");
			resp.setContentLength(bodyHtml.getBytes(StandardCharsets.UTF_8).length);
			resp.getWriter().write(bodyHtml);
			
			return;

		}
		
		chain.doFilter(req, resp);
		
	}
	

	/*
	 * Returns:
	 * 
		<!DOCTYPE html>
		<head lang="en">
		  <meta charset="UTF-8"/>
  		  <title>Information</title>
		</head>
		<body>
		  <div>
			<h1>Values for ShopifyApp [ProtectedResource]</h1>
			<p>
				apiKey: <span th:text='${#authentication.principal.attributes.get("shopify_client_api_key")}'>none found</span><br>
				shopOrigin: <span th:text='${#authentication.principal.name}'>none found</span><br>
				login for this session from embedded app?: <span th:text="${#session.getAttribute('SHOPIFY_EMBEDDED_APP') != null} ? ${#session.getAttribute('SHOPIFY_EMBEDDED_APP')} : 'false'">Unknown</span><br>
			</p>
		  </div>
		</body>
		</html>
	 
	 *
	 */
	
	private String generateUserInfoPageHtml(HttpServletRequest req) {
		
		OAuth2User store = getAuthenticationPrincipalForRequest(req);
		String apiKey = (String)store.getAttributes().get("shopify_client_api_key");
		String shopOrigin = (String)store.getName();
		HttpSession session = getHttpSessionForRequest(req);
		boolean isLoginFromEmbedded = false;
		
		if(session != null) {
			isLoginFromEmbedded = session.getAttribute("SHOPIFY_EMBEDDED_APP") != null ? true : false;
		}

		StringBuilder sb = new StringBuilder();
		
		sb.append("<!DOCTYPE html>\n"
				+ "  <head lang=\"en\">\n"
				+ "    <meta charset=\"UTF-8\">\n"
				+ "    <title>Information</title>\n"
				+ "  </head>\n"
				+ "  <body>\n"
				+ "    <div>\n"
				+ "      <h1>Values for ShopifyApp [ProtectedResource]</h1>\n"
				+ "		 <p>\n"
				+ "      apiKey: <span>" + apiKey + "</span><br>\n"
				+ " 	 shopOrigin: <span>" + shopOrigin + "</span><br\n>"
				+ "		 login for this session from embedded app?: <span>" + isLoginFromEmbedded + "</span><br>\n"
				+ "      </p>"
				+ "    </div>\n"
				+ "  </body>\n"
				+ "</html>"
				);
		
		return sb.toString();
		
	}
	
	private OAuth2User getAuthenticationPrincipalForRequest(HttpServletRequest req) {
		return (OAuth2User)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
	}
	
	private HttpSession getHttpSessionForRequest(HttpServletRequest req) {
		return req.getSession(false);
		
	}
	
	private boolean isAuthenticated() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		
		if(auth instanceof OAuth2AuthenticationToken) {
			return true;
		}
		
		return false;

	}
	
	private boolean isUserInfoRequest(HttpServletRequest req) {
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
			return uri.equals(userInfoPathShopify);
		}

		return uri.equals(req.getContextPath() + userInfoPathShopify);
		
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
