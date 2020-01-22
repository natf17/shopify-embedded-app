package com.ppublica.shopify.security.configuration;

import java.util.Map;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ShopifyPathsTests {
	private String defaultInstallPath = "/install";
	private String defaultAnyInstallPath = "/install/**";
	private String defaultAuthorizationRedirectPath = "/login/app/oauth2/code";
	private String defaultAnyAuthorizationRedirectPath = "/login/app/oauth2/code/**";
	private String defaultLoginEndpoint = "/init";
	private String defaultLogoutEndpoint = "/logout";
	private String defaultAuthenticationFailureUri = "/auth/error";
	private String defaultUninstallUri = "/store/uninstall";
	private String defaultUserInfoPagePath = "/info";

	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyPaths.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}

	@Test
	public void noArgConstructorThenUseDefaults() {
		ShopifyPaths sP = new ShopifyPaths();
		
		Assert.assertFalse(sP.isCustomAuthenticationFailureUri());
		Assert.assertFalse(sP.isCustomAuthorizationRedirectPath());
		Assert.assertFalse(sP.isCustomInstallPath());
		Assert.assertFalse(sP.isCustomLoginEndpoint());
		Assert.assertFalse(sP.isCustomLogoutEndpoint());
		Assert.assertFalse(sP.isCustomUninstallUri());
		Assert.assertFalse(sP.isUserInfoPageEnabled());

		
		Assert.assertEquals(this.defaultAnyAuthorizationRedirectPath, sP.getAnyAuthorizationRedirectPath());
		Assert.assertEquals(this.defaultAnyInstallPath, sP.getAnyInstallPath());
		Assert.assertEquals(this.defaultAuthenticationFailureUri, sP.getAuthenticationFailureUri());
		Assert.assertEquals(this.defaultAuthorizationRedirectPath, sP.getAuthorizationRedirectPath());
		Assert.assertEquals(this.defaultInstallPath, sP.getInstallPath());
		Assert.assertEquals(this.defaultLoginEndpoint, sP.getLoginEndpoint());
		Assert.assertEquals(this.defaultLogoutEndpoint, sP.getLogoutEndpoint());
		Assert.assertEquals(0, sP.getMenuLinks().size());
		Assert.assertEquals(this.defaultUninstallUri, sP.getUninstallUri());
		Assert.assertEquals(this.defaultUserInfoPagePath, sP.getUserInfoPagePath());
	}
	
	@Test
	public void emptyStringsConstructorThenUseDefaults() {
		ShopifyPaths sP = new ShopifyPaths("", "", "", "", "", "", false, "");
		
		Assert.assertFalse(sP.isCustomAuthenticationFailureUri());
		Assert.assertFalse(sP.isCustomAuthorizationRedirectPath());
		Assert.assertFalse(sP.isCustomInstallPath());
		Assert.assertFalse(sP.isCustomLoginEndpoint());
		Assert.assertFalse(sP.isCustomLogoutEndpoint());
		Assert.assertFalse(sP.isCustomUninstallUri());
		Assert.assertFalse(sP.isUserInfoPageEnabled());
		
		Assert.assertEquals(this.defaultAnyAuthorizationRedirectPath, sP.getAnyAuthorizationRedirectPath());
		Assert.assertEquals(this.defaultAnyInstallPath, sP.getAnyInstallPath());
		Assert.assertEquals(this.defaultAuthenticationFailureUri, sP.getAuthenticationFailureUri());
		Assert.assertEquals(this.defaultAuthorizationRedirectPath, sP.getAuthorizationRedirectPath());
		Assert.assertEquals(this.defaultInstallPath, sP.getInstallPath());
		Assert.assertEquals(this.defaultLoginEndpoint, sP.getLoginEndpoint());
		Assert.assertEquals(this.defaultLogoutEndpoint, sP.getLogoutEndpoint());
		Assert.assertEquals(0, sP.getMenuLinks().size());
		Assert.assertEquals(this.defaultUninstallUri, sP.getUninstallUri());
		Assert.assertEquals(this.defaultUserInfoPagePath, sP.getUserInfoPagePath());
	}
	
	
	@Test
	public void customPathsInConstructorThenConstructCustomPaths() {
		ShopifyPaths sP = new ShopifyPaths("/otherInstallPath", "/otherAuthPath", "/otherLoginPath",
											"/otherLogoutPath", "/otherAuthFailureUri", "/otherUninstallUri", true, "");
		
		Assert.assertTrue(sP.isCustomAuthenticationFailureUri());
		Assert.assertTrue(sP.isCustomAuthorizationRedirectPath());
		Assert.assertTrue(sP.isCustomInstallPath());
		Assert.assertTrue(sP.isCustomLoginEndpoint());
		Assert.assertTrue(sP.isCustomLogoutEndpoint());
		Assert.assertTrue(sP.isCustomUninstallUri());
		Assert.assertTrue(sP.isUserInfoPageEnabled());
		
		Assert.assertEquals("/otherAuthPath/**", sP.getAnyAuthorizationRedirectPath());
		Assert.assertEquals("/otherInstallPath/**", sP.getAnyInstallPath());
		Assert.assertEquals("/otherAuthFailureUri", sP.getAuthenticationFailureUri());
		Assert.assertEquals("/otherAuthPath", sP.getAuthorizationRedirectPath());
		Assert.assertEquals("/otherInstallPath", sP.getInstallPath());
		Assert.assertEquals("/otherLoginPath", sP.getLoginEndpoint());
		Assert.assertEquals("/otherLogoutPath", sP.getLogoutEndpoint());
		Assert.assertEquals(0, sP.getMenuLinks().size());
		Assert.assertEquals("/otherUninstallUri", sP.getUninstallUri());
		Assert.assertEquals("/info", sP.getUserInfoPagePath());
	}
	
	@Test
	public void constructorCorrectlyProcessMenuLinks() {
		String menuLinksEntryFromProperties = "key1:val1";
		
		ShopifyPaths sP = new ShopifyPaths("", "", "", "", "", "", false, menuLinksEntryFromProperties);

		Map<String,String> links = sP.getMenuLinks();
		
		Assert.assertEquals(1, links.size());
		Assert.assertEquals("val1", links.get("key1"));
	}
	
	@Test
	public void constructorCorrectlyProcessMultipleMenuLinks() {
		String menuLinksEntryFromProperties = "key1:val1,key2:val2";
		
		ShopifyPaths sP = new ShopifyPaths("", "", "", "", "", "", false, menuLinksEntryFromProperties);

		Map<String,String> links = sP.getMenuLinks();
		
		Assert.assertEquals(2, links.size());
		Assert.assertEquals("val1", links.get("key1"));
		Assert.assertEquals("val2", links.get("key2"));
	}
	
	@Test
	public void constructorCorrectlyProcessMenuLinksContainsSpaceBetweenEntries() {
		String menuLinksEntryFromProperties = "key1:val1, key2:val2";
		
		ShopifyPaths sP = new ShopifyPaths("", "", "", "", "", "", false, menuLinksEntryFromProperties);

		Map<String,String> links = sP.getMenuLinks();
		
		Assert.assertEquals(2, links.size());
		Assert.assertEquals("val1", links.get("key1"));
		Assert.assertEquals("val2", links.get("key2"));
	}
	
	@Test
	public void constructorCorrectlyProcessMenuLinksContainsSpaceAfterColon() {
		String menuLinksEntryFromProperties = "key1: val1,key2: val2";
		
		ShopifyPaths sP = new ShopifyPaths("", "", "", "", "", "", false, menuLinksEntryFromProperties);

		Map<String,String> links = sP.getMenuLinks();
		
		Assert.assertEquals(2, links.size());
		Assert.assertEquals("val1", links.get("key1"));
		Assert.assertEquals("val2", links.get("key2"));
	}
	
}
