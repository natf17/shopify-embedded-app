package com.ppublica.shopify.security.configurer.delegates;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doReturn;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpSession;

import com.ppublica.shopify.security.configuration.ShopifyPaths;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.context.WebApplicationContext;

import com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer;
import com.ppublica.shopify.security.service.DefaultShopifyUserService;

import com.ppublica.shopify.security.service.ShopifyStore;
import com.ppublica.shopify.security.web.NoRedirectSuccessHandler;
import com.ppublica.shopify.security.web.ShopifyAuthorizationCodeTokenResponseClient;
import com.ppublica.shopify.security.web.ShopifyOAuth2AuthorizationRequestResolver;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class ShopifyOAuth2Tests {

	@Autowired
	WebApplicationContext wac;

	@Autowired
	Filter springSecurityFilterChain;

	@Autowired
	OAuth2AuthorizationRequestResolver shopifyOAuth2AuthorizationRequestResolver;

	@Autowired
	ShopifyAuthorizationCodeTokenResponseClient responseClient;

	@Autowired
	NoRedirectSuccessHandler successHandler;

	@Autowired
	DefaultShopifyUserService userService;

	@Autowired
	ShopifyPaths shopifyPaths;

	@Autowired
	ClientRegistration clientRegistration;

	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyOAuth2.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}

	/*
	 * OAuth2AuthorizationRequestResolver:
	 * If not explicitly set, OAuth2LoginConfigurer uses authorizationRequestBaseUri, or default uri to build a default.
	 *
	 * Assert: the configurer's is invoked.
	 */
	@Test
	public void oAuth2AuthorizationRequestResolverInvoked() throws Exception {
		MockHttpServletRequest req = new MockHttpServletRequest("GET", "/install/shopify");
		//this.mockMvc.perform(get("/install/shopify")).andReturn();
		MockHttpServletResponse resp = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);

		springSecurityFilterChain.doFilter(req, resp, chain);
		verify(shopifyOAuth2AuthorizationRequestResolver, times(1)).resolve(any());


	}


	/*
	 * OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>:
	 * If not explicitly set, OAuth2LoginConfigurer uses a default.
	 *
	 * Assert: the configurer's is invoked.
	 */
	@Test
	@DirtiesContext
	public void oAuth2AccessTokenResponseClientInvoked() throws Exception {
		MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login/app/oauth2/code/shopify");
		req.setServletPath("/login/app/oauth2/code/shopify");
		req.setParameter("code", "123");
		req.setParameter("shop", "testStore");
		req.setParameter("state", "state-123");
		MockHttpServletResponse resp = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);

		// add an OAuth2AuthorizationRequest to the session
		Map<String, Object> additionalParameters = new HashMap<>();
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "shopify");


		Map<String, OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>();
		OAuth2AuthorizationRequest oAuthReq = OAuth2AuthorizationRequest.authorizationCode()
											.clientId("client-id")
											.authorizationUri("https://from-test.com/authUri")
											.redirectUri("http://localhost/login/app/oauth2/code/shopify")
											.scopes(new HashSet<>(Arrays.asList("read_prod")))
											.state("state-123")
											.additionalParameters(additionalParameters)
											.attributes(attributes)
											.build();
		authorizationRequests.put("state-123", oAuthReq);

		HttpSession mockSession = mock(HttpSession.class);
		when(mockSession.getAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST")).thenReturn(authorizationRequests);
		when(mockSession.getId()).thenReturn("val");

		req.setSession(mockSession);

		try {
			springSecurityFilterChain.doFilter(req, resp, chain);

		} catch(NullPointerException exc) { }

		verify(mockSession, times(1)).getAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST");
		verify(responseClient, times(1)).getTokenResponse(any());

	}


	/*
	 * AuthenticationSuccessHandler:
	 * If not explicitly set, OAuth2LoginConfigurer uses the default SavedRequestAwareAuthenticationSuccessHandler.
	 *
	 * Assert: the configurer's is invoked.
	 */
	@Test
	@DirtiesContext
	public void authenticationSuccessHandlerInvoked() throws Exception {
		MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login/app/oauth2/code/shopify");
		req.setServletPath("/login/app/oauth2/code/shopify");
		req.setParameter("code", "123");
		req.setParameter("shop", "testStore");
		req.setParameter("state", "state-123");
		MockHttpServletResponse resp = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);

		// add an OAuth2AuthorizationRequest to the session
		Map<String, Object> additionalParameters = new HashMap<>();
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "shopify");


		Map<String, OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>();
		OAuth2AuthorizationRequest oAuthReq = OAuth2AuthorizationRequest.authorizationCode()
											.clientId("client-id")
											.authorizationUri("https://from-test.com/authUri")
											.redirectUri("http://localhost/login/app/oauth2/code/shopify")
											.scopes(new HashSet<>(Arrays.asList("read_prod")))
											.state("state-123")
											.additionalParameters(additionalParameters)
											.attributes(attributes)
											.build();
		authorizationRequests.put("state-123", oAuthReq);

		HttpSession mockSession = mock(HttpSession.class);
		when(mockSession.getAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST")).thenReturn(authorizationRequests);
		when(mockSession.getId()).thenReturn("for_ChangeSessionIdAuthenticationStrategy");
		req.setSession(mockSession);

		doReturn(getSampleOAuth2AccessTokenResponse()).when(responseClient).getTokenResponse(any());
		doReturn(getSampleOAuth2User()).when(userService).loadUser(any());


		springSecurityFilterChain.doFilter(req, resp, chain);

		verify(userService, times(1)).loadUser(any());
		verify(successHandler, times(1)).onAuthenticationSuccess(any(), any(), any());

	}


	/*
	 * OAuth2UserService<OAuth2UserRequest, OAuth2User>:
	 * If not explicitly set, OAuth2LoginConfigurer searches for a bean.
	 *
	 * Assert: the configurer's is invoked.
	 */
	@Test
	@DirtiesContext
	public void oAuth2UserServiceInvoked() throws Exception {
		MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login/app/oauth2/code/shopify");
		req.setServletPath("/login/app/oauth2/code/shopify");
		req.setParameter("code", "123");
		req.setParameter("shop", "testStore");
		req.setParameter("state", "state-123");
		MockHttpServletResponse resp = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);

		// add an OAuth2AuthorizationRequest to the session
		Map<String, Object> additionalParameters = new HashMap<>();
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "shopify");


		Map<String, OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>();
		OAuth2AuthorizationRequest oAuthReq = OAuth2AuthorizationRequest.authorizationCode()
											.clientId("client-id")
											.authorizationUri("https://from-test.com/authUri")
											.redirectUri("http://localhost/login/app/oauth2/code/shopify")
											.scopes(new HashSet<>(Arrays.asList("read_prod")))
											.state("state-123")
											.additionalParameters(additionalParameters)
											.attributes(attributes)
											.build();
		authorizationRequests.put("state-123", oAuthReq);

		HttpSession mockSession = mock(HttpSession.class);
		when(mockSession.getAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST")).thenReturn(authorizationRequests);

		req.setSession(mockSession);

		doReturn(getSampleOAuth2AccessTokenResponse()).when(responseClient).getTokenResponse(any());

		try {
			springSecurityFilterChain.doFilter(req, resp, chain);

		} catch(NullPointerException exc) { }

		verify(userService, times(1)).loadUser(any());

	}

	private OAuth2User getSampleOAuth2User() {
		return new ShopifyStore("test-store","access-token", "api-key", null);
	}

	private OAuth2AccessTokenResponse getSampleOAuth2AccessTokenResponse() {
		Map<String, Object> additionalParameters = new LinkedHashMap<>();
		additionalParameters.put(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN, "test-store");

		return OAuth2AccessTokenResponse.withToken("access-token")
				.expiresIn(2000L)
				.tokenType(TokenType.BEARER)
				.scopes(new HashSet<>(Arrays.asList("priv-1", "priv-2")))
				.refreshToken(null)
				.additionalParameters(additionalParameters)
				.build();
	}

	@EnableWebSecurity
	static class ApplyCsrfSecurityConfig extends WebSecurityConfigurerAdapter {
		private final ShopifyOAuth2 conf = new ShopifyOAuth2(shopifyPaths(), clientRegistration());

		// disable defaults to prevent configurer in spring.factories from being applied
		public ApplyCsrfSecurityConfig() {
			super(true);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {

			// applying the defaults that had been disabled
			http
				.csrf().and()
				.addFilter(new WebAsyncManagerIntegrationFilter())
				.exceptionHandling().and()
				.headers().and()
				.sessionManagement().and()
				.securityContext().and()
				.requestCache().and()
				.anonymous().and()
				.servletApi().and()
				.apply(new DefaultLoginPageConfigurer<>()).and()
				.logout();

			// apply an AbstractHttpConfigurer
			http.apply(new ShopifySecurityConfigurer<HttpSecurity>() {
				@Override
				public void init (HttpSecurity http) {
					conf.applyShopifyInit(http);
				}
				@Override
				public void configure(HttpSecurity http) {
					conf.applyShopifyConfig(http);
				}

			});

			http.authorizeRequests()
					.anyRequest().permitAll().and()
				.oauth2Login().and()
				.requiresChannel();
		}

		/*
		 * Beans picked up by ShopifyBeansUtils
		 */

		@Bean
		public ClientRegistrationRepository testRepo() {
			ClientRegistration reg =
					ClientRegistration.withRegistrationId("shopify")
            .clientId("client-id")
            .clientSecret("client-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
            .scope(new HashSet<>(Arrays.asList("read_prod")))
            .authorizationUri("https://{shop}/admin/oauth/authorize")
            .tokenUri("https://{shop}/admin/oauth/access_token")
            .clientName("Shopify")
            .build();
	        return new InMemoryClientRegistrationRepository(reg);

		}

		@Bean
		public ShopifyOAuth2AuthorizationRequestResolver shopifyOAuth2AuthorizationRequestResolver() {
			return mock(ShopifyOAuth2AuthorizationRequestResolver.class);
		}

		@Bean
		public ShopifyAuthorizationCodeTokenResponseClient accessTokenResponseClient() {
			return mock(ShopifyAuthorizationCodeTokenResponseClient.class);
		}

		@Bean
		public NoRedirectSuccessHandler successHandler() {
			return mock(NoRedirectSuccessHandler.class);
		}

		@Bean
		public DefaultShopifyUserService userService() {
			return mock(DefaultShopifyUserService.class);
		}

		// picked up by OAuth2ClientConfigurerUtils
		@Bean
		public OAuth2AuthorizedClientService authorizedClientService() {
			return mock(OAuth2AuthorizedClientService.class);
		}

		@Bean
		public ShopifyPaths shopifyPaths() {
			return mock(ShopifyPaths.class);
		}

		@Bean
		public ClientRegistration clientRegistration() {
			return mock(ClientRegistration.class);
		}

	}

}
