package com.ppublica.shopify.security.configurer.delegates;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

import javax.servlet.Filter;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class ShopifyLogoutTests {

	@Autowired
	WebApplicationContext wac;

	@Autowired
	Filter springSecurityFilterChain;
	
	MockMvc mockMvc;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyLogout.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	
	@Before
	public void setup() throws Exception {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.apply(springSecurity(springSecurityFilterChain))
				.build();
	
	}
	
	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}
	
	@Test
	public void logoutSuccessThenRedirectAndOverrides() throws Exception {
		/*
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		ShopifyStore principal = new ShopifyStore("test-store", "oauth-token", "api-key", null);
		Authentication auth = new OAuth2AuthenticationToken(principal, null, "shopify");
		context.setAuthentication(auth);
		*/
		
		this.mockMvc.perform(post("/customLogout").with(csrf()))
			.andExpect(redirectedUrlPattern("/customLogin/**"))
			.andReturn();
		
	}
	@Test
	public void logoutOverrides() throws Exception {
		/*
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		ShopifyStore principal = new ShopifyStore("test-store", "oauth-token", "api-key", null);
		Authentication auth = new OAuth2AuthenticationToken(principal, null, "shopify");
		context.setAuthentication(auth);
		*/
		
		this.mockMvc.perform(post("/other").with(csrf()))
			.andExpect(status().isForbidden())
			.andReturn();
		
	}
	
	@EnableWebSecurity
	static class ApplyCsrfSecurityConfig extends WebSecurityConfigurerAdapter {
		ShopifyLogout logout = new ShopifyLogout("/customLogin", "/customLogout");
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
					logout.applyShopifyInit(http);
				}
				@Override
				public void configure(HttpSecurity http) {
					logout.applyShopifyConfig(http);
				}

			});
			
			http.authorizeRequests()
					.antMatchers("/customLogin").permitAll()
					.anyRequest().authenticated().and()
				.requiresChannel()
					.anyRequest()
						.requiresInsecure().and().logout().logoutUrl("/other");
		}
		
	}
	
}
