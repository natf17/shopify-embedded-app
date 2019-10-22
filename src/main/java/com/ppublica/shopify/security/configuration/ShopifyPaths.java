package com.ppublica.shopify.security.configuration;

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
	
	private boolean isCustomInstallPath;
	private boolean isCustomAuthorizationRedirectPath;
	private boolean isCustomLoginEndpoint;
	private boolean isCustomLogoutEndpoint;
	private boolean isCustomAuthenticationFailureUri;
	private boolean isCustomUninstallUri;
	
	public ShopifyPaths(String installPath, String authorizationRedirectPath, String loginEndpoint,
						String logoutEndpoint, String authenticationFailureUri, String uninstallUri) {
		
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
	
}
