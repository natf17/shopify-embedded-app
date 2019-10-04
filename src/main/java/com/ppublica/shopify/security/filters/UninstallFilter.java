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

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configuration.SecurityBeansConfig;


/*
 * If the request matches uninstallEndpoint/shopify, by default "/store/uninstall/shopify":
 * 		1. Delegate to ShopifyVerificationStrategy to validate the header
 * 		2. Call doUninstall(...,...)
 * 		3. Call uninstallSuccess(...,..) upon success
 */
public class UninstallFilter implements Filter {
	
	private AntPathRequestMatcher matcher;
	private ShopifyVerificationStrategy verificationStrategy;
	private OAuth2AuthorizedClientService clientService;
	private HttpMessageConverter<Object> messageConverter;
	private static final String REGISTRATION_ID = SecurityBeansConfig.SHOPIFY_REGISTRATION_ID;
	
	
	public UninstallFilter(String uninstallEndpoint, ShopifyVerificationStrategy verificationStrategy, OAuth2AuthorizedClientService clientService, HttpMessageConverter<Object> converter) {
		this.matcher = uninstallEndpoint.endsWith(REGISTRATION_ID) ? new AntPathRequestMatcher(uninstallEndpoint) : new AntPathRequestMatcher(uninstallEndpoint + "/" + REGISTRATION_ID);
		this.verificationStrategy = verificationStrategy;
		this.clientService = clientService;
		this.messageConverter = converter;
	}

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
			doUninstall(req, resp);
			
			return;
		}
		
		uninstallFailure(req, resp);
		
		return;
		
		
	}
	
	public boolean matches(HttpServletRequest request) {
		return this.matcher.matches(request);
	
		
	}
	
	/*
	 * Attempt to uninstall the store specified in the body:
	 * 	1. Get the request body as an UninstallMessage object
	 * 	2. Pass the shop domain from the body to tokenService to uninstall
	 */
	protected void doUninstall(HttpServletRequest request, HttpServletResponse response) throws IOException{
		UninstallMessage body = this.extractBody(request);

		if(body == null) {
			uninstallFailure(request, response);
			return;
		} 
		String storeName = body.getShop_domain();

		if(storeName == null || storeName.isEmpty()) {
			uninstallFailure(request, response);
			return;
		}

		this.clientService.removeAuthorizedClient(REGISTRATION_ID, storeName);
		uninstallSuccess(request, response);
	}
	
	protected void uninstallSuccess(HttpServletRequest req, HttpServletResponse resp) {

		resp.setStatus(200);
	}
	
	protected void uninstallFailure(HttpServletRequest req, HttpServletResponse resp) throws IOException{

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
