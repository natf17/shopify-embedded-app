# In Progress: This project replaces the shopify-spring-boot-embedded-app project, as it aims to be entirely decoupled from the importing project.


Expected database schema:

StoreAccessTokens
id - storeDomain - tokenType - tokenValue - salt - issuedAt - expiresAt - scopes


/*
	 * This controller can be reached via different scenarios:
	 * 
	 * 1. Authenticated: Shopify made the request and the store had already installed the app (embedded app scenario)
	 * 2. Anonymous: 
	 * 			- Shopify made the request but it's the store's first time
	 * 			- the request did not come from Shopify but a store param was included (let Shopify log the user in)
	 * 			- User makes a request (not as an embedded app) without providing a store param (a redirect is performed)
	 * 
	 */
	
	//@RequestMapping(path = ShopifySecurityConfigurer.INSTALL_PATH + "/" + SecurityBeansConfig.SHOPIFY_REGISTRATION_ID, method = RequestMethod.GET)
	public String installAndHome() {

		return "home";
	}
	
	/*
	 * Redirect to /install/shopify
	 */
	//@RequestMapping(path = ShopifySecurityConfigurer.INSTALL_PATH , method = RequestMethod.GET)
	public String installRedirect() {
		return "redirect:" ;//+ ShopifySecurityConfigurer.INSTALL_PATH + "/" + SecurityBeansConfig.SHOPIFY_REGISTRATION_ID;
	}
	
	/*
	 * Called when a store parameter was not given to ANY_INSTALL_PATH
	 * 
	 */
	//@RequestMapping(path = ShopifySecurityConfigurer.LOGIN_ENDPOINT, method = RequestMethod.GET)
	public String selectStore() {
		return "selectStore";
	}
	
	/*
	 * Only to be called during the OAuth flow
	 * 
	 */
	//@RequestMapping(path = ShopifySecurityConfigurer.ANY_AUTHORIZATION_REDIRECT_PATH, method = RequestMethod.GET)
	public String installationSuccess() {

		return "success";
	}
	
	/*
	 * To be called when an error occurs during authentication
	 * 
	 */
	//@RequestMapping(path = ShopifySecurityConfigurer.AUTHENTICATION_FALURE_URL, method = RequestMethod.GET)
	public String authError() {

		return "authError";
	}
	@RequestMapping(path = "/info", method = RequestMethod.GET)
	public String info() {
		
				
		return "info";
	}
