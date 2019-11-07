package com.ppublica.shopify.security.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/*
 * 
 * This strategy generates an HTML page that is seen after successful completion of OAuth2 authorization with
 * Shopify.
 * 
 * Therefore, this strategy is invoked after initial installation in the embedded app, or after
 * authenticating from outside the embedded app.
 *
 */
public class GenerateDefaultAuthorizationPageStrategy implements AuthorizationSuccessPageStrategy {

	private Map<String, String> menuLinks;

	public GenerateDefaultAuthorizationPageStrategy(Map<String,String> menuLinks) {
		this.menuLinks = menuLinks;
	}
	@Override
	public void handleAuthorizationPage(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		
		String bodyHtml = generateAuthorizationRedirectPageHtml((HttpServletRequest)request);
		response.setContentType("text/html;charset=UTF-8");
		response.setContentLength(bodyHtml.getBytes(StandardCharsets.UTF_8).length);
		response.getWriter().write(bodyHtml);
		
		return;
		
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

}
