package com.ppublica.shopify.security.configuration;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/* 
 * 
 */
/**
 * Contains all the default Shopify OAuth-related paths, and keeps track of whether or not a custom path has been
 * provided.
 * 
 * @author N F
 *
 */
public class ShopifyPaths {
	private final Log logger = LogFactory.getLog(ShopifyPaths.class);

	private String installPath = "/install";
	private String anyInstallPath = "/install/**";
	private String authorizationRedirectPath = "/login/app/oauth2/code";
	private String anyAuthorizationRedirectPath = "/login/app/oauth2/code/**";
	private String loginEndpoint = "/init";
	private String logoutEndpoint = "/logout";
	private String authenticationFailureUri = "/auth/error";
	private String uninstallUri = "/store/uninstall";
	private String userInfoPagePath = "/info";
	
	private boolean isCustomInstallPath;
	private boolean isCustomAuthorizationRedirectPath;
	private boolean isCustomLoginEndpoint;
	private boolean isCustomLogoutEndpoint;
	private boolean isCustomAuthenticationFailureUri;
	private boolean isCustomUninstallUri;
	private boolean isUserInfoPageEnabled;
	private Map<String,String> menuLinks;
	
	/**
	 * Create a ShopifyPaths with the default paths.
	 * 
	 */
	public ShopifyPaths() {
		this(null,null,null,null,null,null,null, null);
	}
	
	/**
	 * Build a ShopifyPaths object with custom paths. If any of the strings is neither null nor empty, it will 
	 * be immediately considered as a custom path. This allows for a default path to be used as a custom path. 
	 * For example, although "/install" is the default install path, setting it directly will make this path a 
	 * custom path.
	 *  
	 * @param installPath Path to install the app with Shopify
	 * @param authorizationRedirectPath Path Shopify redirects to with the auth code
	 * @param loginEndpoint Path to select a store to log into
	 * @param logoutEndpoint Path to log out
	 * @param authenticationFailureUri Path that handles OAuth failure
	 * @param uninstallUri Path Shopify calls to uninstall
	 * @param enableInfoPath Whether to create an app info page
	 * @param menuLinks A string with a map of labels and links
	 */
	public ShopifyPaths(String installPath, String authorizationRedirectPath, String loginEndpoint,
						String logoutEndpoint, String authenticationFailureUri, String uninstallUri, Boolean enableInfoPath,
						String menuLinks) {
		
		if(installPath != null && !installPath.trim().isEmpty()) {
			this.installPath = installPath;
			this.anyInstallPath = installPath + "/**";
			this.isCustomInstallPath = true;
		}

		if(authorizationRedirectPath != null && !authorizationRedirectPath.trim().isEmpty()) {
			this.authorizationRedirectPath = authorizationRedirectPath;
			this.anyAuthorizationRedirectPath = authorizationRedirectPath + "/**";
			this.isCustomAuthorizationRedirectPath = true;
		}

		if(loginEndpoint != null && !loginEndpoint.trim().isEmpty()) {
			this.loginEndpoint = loginEndpoint;
			this.isCustomLoginEndpoint = true;
		}

		if(logoutEndpoint != null && !logoutEndpoint.trim().isEmpty()) {
			this.logoutEndpoint = logoutEndpoint;
			this.isCustomLogoutEndpoint = true;
		}

		if(authenticationFailureUri != null && !authenticationFailureUri.trim().isEmpty()) {
			this.authenticationFailureUri = authenticationFailureUri;
			this.isCustomAuthenticationFailureUri = true;
		}

		if(uninstallUri != null && !uninstallUri.trim().isEmpty()) {
			this.uninstallUri = uninstallUri;
			this.isCustomUninstallUri = true;
		}
		
		if(enableInfoPath != null && enableInfoPath == true) {
			this.isUserInfoPageEnabled = true;
		}
		
		this.menuLinks = new LinkedHashMap<>();
		if(menuLinks != null && !menuLinks.trim().isEmpty()) {
			this.menuLinks.putAll(processMenuLinks(menuLinks));
		}
		
		if(logger.isDebugEnabled()) {
			logger.debug("***ShopifyPaths using: ***");
			logger.debug("Installation:           " + installPath);
			logger.debug("Authorization redirect: " + authorizationRedirectPath);
			logger.debug("Login:                  " + loginEndpoint);
			logger.debug("Logout:                 " + logoutEndpoint);
			logger.debug("Authentication failure: " + authenticationFailureUri);
			logger.debug("Uninstallation path:    " + uninstallUri);
			logger.debug("Should enable app info: " + isUserInfoPageEnabled);
			logger.debug("Menu link:              " + menuLinks);

		}
	}
	
	
	public String getInstallPath() {
		return this.installPath;
	}
	
	public String getAnyInstallPath() {
		return this.anyInstallPath;
	}
	
	public boolean isCustomInstallPath() {
		return this.isCustomInstallPath;
	}
	
	public String getAuthorizationRedirectPath() {
		return this.authorizationRedirectPath;
	}
	
	public String getAnyAuthorizationRedirectPath() {
		return this.anyAuthorizationRedirectPath;
	}
	
	public boolean isCustomAuthorizationRedirectPath() {
		return this.isCustomAuthorizationRedirectPath;
	}
	
	public String getLoginEndpoint() {
		return this.loginEndpoint;
	}
	
	public boolean isCustomLoginEndpoint() {
		return this.isCustomLoginEndpoint;
	}
	
	public String getLogoutEndpoint() {
		return this.logoutEndpoint;
	}
	
	public boolean isCustomLogoutEndpoint() {
		return this.isCustomLogoutEndpoint;
	}
	
	public String getAuthenticationFailureUri() {
		return this.authenticationFailureUri;
	}
	
	public boolean isCustomAuthenticationFailureUri() {
		return this.isCustomAuthenticationFailureUri;
	}
	
	public String getUninstallUri() {
		return this.uninstallUri;
	}
	
	public boolean isCustomUninstallUri() {
		return this.isCustomUninstallUri;
	}
	
	public String getUserInfoPagePath() {
		return this.userInfoPagePath;
	}
	
	public boolean isUserInfoPageEnabled() {
		return this.isUserInfoPageEnabled;
	}
	
	public Map<String, String> getMenuLinks() {
		return this.menuLinks;
	}
	/*
	 * "key1:val1,key2:val2"
	 */
	
	/**
	 * Process a string with the pattern "key1:val1,key2:val2" as a map.
	 * 
	 * @param source The string
	 * @return The contents of the string in a a Map
	 */
	protected LinkedHashMap<String, String> processMenuLinks(String source) {
		LinkedHashMap<String, String> menuLinks = new LinkedHashMap<>();
		
		String[] pieces = source.trim().split(",");
		
		String keyVal = "";
		String[] keyValPieces = {};
		for(String piece : pieces) {
			keyVal = piece.trim();
			keyValPieces = keyVal.split(":");
			
			//expects 2 pieces
			if(keyValPieces.length != 2) {
				throw new RuntimeException("Error parsing menu links");
			}
			
			menuLinks.put(keyValPieces[0], keyValPieces[1].trim());
			
		}
		
		return menuLinks;
	}
	
}
