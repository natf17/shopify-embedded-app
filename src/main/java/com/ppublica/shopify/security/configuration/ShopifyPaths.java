package com.ppublica.shopify.security.configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/* 
 * 
 */

public class ShopifyPaths {
	
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
	
	public ShopifyPaths() {
		this(null,null,null,null,null,null,null, null);
	}
	
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
