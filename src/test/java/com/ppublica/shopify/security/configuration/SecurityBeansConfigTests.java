package com.ppublica.shopify.security.configuration;

import static org.mockito.Mockito.mock;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configurer.delegates.ShopifyChannelSecurity;
import com.ppublica.shopify.security.configurer.delegates.ShopifyCsrf;
import com.ppublica.shopify.security.configurer.delegates.ShopifyHeaders;
import com.ppublica.shopify.security.configurer.delegates.ShopifyLogout;
import com.ppublica.shopify.security.configurer.delegates.ShopifyOAuth2;
import com.ppublica.shopify.security.repository.TokenRepository;
import com.ppublica.shopify.security.service.TokenService;
import com.ppublica.shopify.security.web.AuthorizationSuccessPageStrategy;
import com.ppublica.shopify.security.web.ForwardAuthorizationSuccessPageStrategy;
import com.ppublica.shopify.security.web.GenerateDefaultAuthorizationPageStrategy;
import com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;

public class SecurityBeansConfigTests {
	
	private AnnotationConfigWebApplicationContext ctx;
	
	@Before
	public void setup() {
		ctx = new AnnotationConfigWebApplicationContext();
		ctx.register(SecurityBeansConfig.class);
		ctx.register(ApplicationDependencies.class);

	}

	@After
	public void cleanup() {
		if(this.ctx != null) {
			ctx.close();
		}
	}
	
	@Test
	public void allBeansLoaded() {
		ctx.setEnvironment(getBareMockEnvironment());
		ctx.refresh();
		
		Assert.assertNotNull(ctx.getBean(TokenRepository.class));
		Assert.assertNotNull(ctx.getBean(ShopifyPaths.class));
		Assert.assertNotNull(ctx.getBean(CipherPassword.class));
		Assert.assertNotNull(ctx.getBean(OAuth2UserService.class));
		Assert.assertNotNull(ctx.getBean(OAuth2AccessTokenResponseClient.class));
		Assert.assertNotNull(ctx.getBean(AuthorizationSuccessPageStrategy.class));
		Assert.assertNotNull(ctx.getBean(AuthenticationSuccessHandler.class));
		Assert.assertNotNull(ctx.getBean(ClientRegistration.class));
		Assert.assertNotNull(ctx.getBean(ClientRegistrationRepository.class));
		Assert.assertNotNull(ctx.getBean(TokenService.class));
		Assert.assertNotNull(ctx.getBean(OAuth2AuthorizedClientService.class));
		Assert.assertNotNull(ctx.getBean(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.class));
		Assert.assertNotNull(ctx.getBean(OAuth2AuthorizationRequestResolver.class));
		Assert.assertNotNull(ctx.getBean(ShopifyVerificationStrategy.class));
		Assert.assertNotNull(ctx.getBean(CsrfTokenRepository.class));
		Assert.assertNotNull(ctx.getBean(ShopifyHeaders.class));
		Assert.assertNotNull(ctx.getBean(ShopifyChannelSecurity.class));
		Assert.assertNotNull(ctx.getBean(ShopifyCsrf.class));
		Assert.assertNotNull(ctx.getBean(ShopifyLogout.class));
		Assert.assertNotNull(ctx.getBean(ShopifyOAuth2.class));
		

	}
	
	@Test
	public void shopifyPathsBeanCorrectlyInitializedNoArg() {
		ctx.setEnvironment(getBareMockEnvironment());
		ctx.refresh();
		
		ShopifyPaths shopifyPathsBean = ctx.getBean(ShopifyPaths.class);

		Assert.assertFalse(shopifyPathsBean.isCustomAuthenticationFailureUri());
		Assert.assertFalse(shopifyPathsBean.isCustomAuthorizationRedirectPath());
		Assert.assertFalse(shopifyPathsBean.isCustomInstallPath());
		Assert.assertFalse(shopifyPathsBean.isCustomLoginEndpoint());
		Assert.assertFalse(shopifyPathsBean.isCustomLogoutEndpoint());
		Assert.assertFalse(shopifyPathsBean.isCustomUninstallUri());
		Assert.assertFalse(shopifyPathsBean.isUserInfoPageEnabled());

	}
	
	
	@Test
	public void shopifyPathsBeanCorrectlyInitializedCustomPaths() {
		MockEnvironment env = getBareMockEnvironment();
		env.setProperty("ppublica.shopify.security.endpoints.install", "/customInstall");
		env.setProperty("ppublica.shopify.security.endpoints.authorization-redirect", "/cumstomAuthRedirect");
		env.setProperty("ppublica.shopify.security.endpoints.login", "/customLogin");
		env.setProperty("ppublica.shopify.security.endpoints.logout", "/customLogout");
		env.setProperty("ppublica.shopify.security.endpoints.authentication-failure", "/authFailure");
		env.setProperty("ppublica.shopify.security.endpoints.uninstall", "/customUninstall");
		env.setProperty("ppublica.shopify.security.endpoints.enable-default-info-page", "true");
		env.setProperty("ppublica.shopify.security.endpoints.menu-link", "key1:val1");


		ctx.setEnvironment(env);
		ctx.refresh();
		
		ShopifyPaths shopifyPathsBean = ctx.getBean(ShopifyPaths.class);

		Assert.assertEquals("/customInstall", shopifyPathsBean.getInstallPath());
		Assert.assertEquals("/authFailure", shopifyPathsBean.getAuthenticationFailureUri());
		Assert.assertEquals("/cumstomAuthRedirect", shopifyPathsBean.getAuthorizationRedirectPath());
		Assert.assertEquals("/customLogin", shopifyPathsBean.getLoginEndpoint());
		Assert.assertEquals("/customLogout", shopifyPathsBean.getLogoutEndpoint());
		Assert.assertEquals("/customUninstall", shopifyPathsBean.getUninstallUri());
		Assert.assertEquals("/info", shopifyPathsBean.getUserInfoPagePath());
		Assert.assertEquals(1, shopifyPathsBean.getMenuLinks().size());
		Assert.assertTrue(shopifyPathsBean.isUserInfoPageEnabled());

	}
	
	@Test
	public void whenCustomAuthorizationRedirectPathThenForwardAuthorizationSuccessPageStrategyBeanCreated() {
		MockEnvironment env = getBareMockEnvironment();
		env.setProperty("ppublica.shopify.security.endpoints.authorization-redirect", "/cumstomAuthRedirect");
		ctx.setEnvironment(env);
		ctx.refresh();
		
		AuthorizationSuccessPageStrategy authorizationSuccessPageStrategy = ctx.getBean(AuthorizationSuccessPageStrategy.class);

		Assert.assertTrue(authorizationSuccessPageStrategy instanceof ForwardAuthorizationSuccessPageStrategy);

	}
	
	@Test
	public void whenDefaultAuthorizationRedirectPathThenForwardAuthorizationSuccessPageStrategyBeanCreated() {
		MockEnvironment env = getBareMockEnvironment();
		ctx.setEnvironment(env);
		ctx.refresh();
		
		AuthorizationSuccessPageStrategy authorizationSuccessPageStrategy = ctx.getBean(AuthorizationSuccessPageStrategy.class);

		Assert.assertTrue(authorizationSuccessPageStrategy instanceof GenerateDefaultAuthorizationPageStrategy);

	}
	
	private MockEnvironment getBareMockEnvironment() {
		MockEnvironment mockEnv = new MockEnvironment();
		mockEnv.setProperty("ppublica.shopify.security.cipher.password", "sample-password");
		mockEnv.setProperty("ppublica.shopify.security.client.client_id", "sample-client-id");
		mockEnv.setProperty("ppublica.shopify.security.client.client_secret", "sample-client-secret");
		mockEnv.setProperty("ppublica.shopify.security.client.scope", "sample-client-scope");
		return mockEnv;
		
	}
	
	@Configuration
	static class ApplicationDependencies {
		@Bean
		JdbcTemplate jdbc() {
			return mock(JdbcTemplate.class);
		}
	}

}
