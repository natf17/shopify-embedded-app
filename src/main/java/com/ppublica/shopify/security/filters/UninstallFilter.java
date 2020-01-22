package com.ppublica.shopify.security.filters;

import java.io.IOException;

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
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configuration.SecurityBeansConfig;


/**
 * This filter uninstalls the requested Shopify store for requests matching uninstallEndpoint/shopify.
 * By default, it matches the path "/store/uninstall/shopify" (see ShopifyPaths).
 * 
 * @author N F
 * @see com.ppublica.shopify.security.configuration.ShopifyPaths
 * @see com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer
 * @see com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy
 *
 */
public class UninstallFilter implements Filter {
	private final Log logger = LogFactory.getLog(UninstallFilter.class);

	private AntPathRequestMatcher matcher;
	private ShopifyVerificationStrategy verificationStrategy;
	private OAuth2AuthorizedClientService clientService;
	private HttpMessageConverter<Object> messageConverter;
	private static final String REGISTRATION_ID = SecurityBeansConfig.SHOPIFY_REGISTRATION_ID;
	
	/**
	 * Build the UninstallFilter. The uninstallEndpoint must end with the registration id as defined in
	 * SecurityBeansConfig.
	 * 
	 * @param uninstallEndpoint To match the uninstall request
	 * @param verificationStrategy To verify the request
	 * @param clientService To remove the store
	 * @param converter To read the body of the message
	 */
	public UninstallFilter(String uninstallEndpoint, ShopifyVerificationStrategy verificationStrategy, OAuth2AuthorizedClientService clientService, HttpMessageConverter<Object> converter) {
		this.matcher = uninstallEndpoint.endsWith(REGISTRATION_ID) ? new AntPathRequestMatcher(uninstallEndpoint) : new AntPathRequestMatcher(uninstallEndpoint + "/" + REGISTRATION_ID);
		this.verificationStrategy = verificationStrategy;
		this.clientService = clientService;
		this.messageConverter = converter;
	}

	/**
	 * Determine if the request path matches the filter, and if so, initiate the uninstallation process.
	 * Upon matching, this method delegates to ShopifyVerificationStrategy to validate the header, calls
	 * doUnninstall(), and finally uninstallSuccess(...,..) upon success.
	 * 
	 * @param request The request
	 * @param response The response
	 * @param chain The security filter chain
	 * @throws IOException When invoking chain
	 * @throws ServletException When invoking the chain
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest)request;
		HttpServletResponse resp = (HttpServletResponse)response;
				
		if(!matches(req)) {
			chain.doFilter(req, response);
			return;
		}
				
		if(this.verificationStrategy.isHeaderShopifyRequest(req, REGISTRATION_ID)) {
			logger.info("Store uninstallation request received");

			doUninstall(req, resp);
			
			return;
		}
				
		uninstallFailure(req, resp);
		
		return;
		
		
	}
	
	/**
	 * Check the request path for a match.
	 * @param request The current request
	 * @return True if there's a match, false otherwise
	 */
	public boolean matches(HttpServletRequest request) {
		return this.matcher.matches(request);
	
		
	}
	
	/**
	 * Attempt to uninstall the store specified in the body. This method gets the request body as an 
	 * UninstallMessage object and then passes the shop domain from the body to tokenService to uninstall.
	 * 
	 * @param request The request
	 * @param response The response
	 * @throws IOException If unable to generate a response
	 */
	protected void doUninstall(HttpServletRequest request, HttpServletResponse response) throws IOException{
		UninstallMessage body = this.extractBody(request);

		if(body == null) {
			uninstallFailure(request, response);
			return;
		} 
		String storeName = body.getShop_domain();

		if(storeName == null || storeName.isEmpty()) {
			logger.debug("No shop_domain found in body");
			uninstallFailure(request, response);
			return;
		}

		this.clientService.removeAuthorizedClient(REGISTRATION_ID, storeName);
		uninstallSuccess(request, response);
	}
	
	/**
	 * Send a 200 status code upon successfully uninstalling the store.
	 * 
	 * @param req The request
	 * @param resp The response
	 */
	protected void uninstallSuccess(HttpServletRequest req, HttpServletResponse resp) {

		resp.setStatus(200);
	}
	
	/**
	 * Send a 403 status code if the uninstallation fails.
	 * @param req The request
	 * @param resp The response
	 * @throws IOException Unable to send an error 
	 */
	protected void uninstallFailure(HttpServletRequest req, HttpServletResponse resp) throws IOException{
		logger.debug("Store uninstallation request failed");

		resp.sendError(403, "This request must come from Shopify");
	}
	
	private UninstallMessage extractBody(HttpServletRequest request) {
		ServletServerHttpRequest message = new ServletServerHttpRequest(request);
		UninstallMessage msg;
		
		try {
			msg = (UninstallMessage)this.messageConverter.read(UninstallMessage.class, message);
		} catch (Exception ex){
			return null;
		}

		return msg;
	}
	
	/**
	 * A representation of the body/payload of an uninstallation request from Shopify.
	 * 
	 * @author N F
	 */
	static class UninstallMessage {
		private String shop_id;
		private String shop_domain;
		
		public void setShop_id(String shop_id) {
			this.shop_id = shop_id;
		}
		
		public String getShop_id() {
			return this.shop_id;
		}
		
		public void setShop_domain(String shop_domain) {
			this.shop_domain = shop_domain;
		}
		
		public String getShop_domain() {
			return this.shop_domain;
		}
		
		
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException { }

	@Override
	public void destroy() { }

}
