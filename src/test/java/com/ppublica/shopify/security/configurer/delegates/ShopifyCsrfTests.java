package com.ppublica.shopify.security.configurer.delegates;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

import javax.servlet.Filter;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.test.annotation.DirtiesContext;
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
public class ShopifyCsrfTests {

	@Autowired
	WebApplicationContext wac;

	@Autowired
	Filter springSecurityFilterChain;
	
	MockMvc mockMvc;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyCsrf.class.getName());
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
	
	@Test
	public void csrfCookieSet() throws Exception {
		this.mockMvc.perform(get("/install"))
			.andExpect(cookie().exists("XSRF-TOKEN"))
			.andReturn();
		
	}
	
	@Test
	public void pathsRequireCsrfValue() throws Exception {
		this.mockMvc.perform(post("/install"))
			.andExpect(status().isForbidden())
			.andReturn();
	}
	
	@Test
	@DirtiesContext
	public void requestWithCsrfSuccess() throws Exception {
		this.mockMvc.perform(post("/install").with(csrf()))
			.andExpect(status().isNotFound())
			.andReturn();
		
	}
	
	@Test
	public void uninstallUriNoCsrfThenSuccess() throws Exception {
		this.mockMvc.perform(post("/uninstallUri"))
			.andExpect(status().isNotFound())
			.andReturn();
	}
	
	@EnableWebSecurity
	static class ApplyCsrfSecurityConfig extends WebSecurityConfigurerAdapter {
		ShopifyCsrf csrf = new ShopifyCsrf("/uninstallUri", getCsrfTokenRepo());
		
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
					csrf.applyShopifyInit(http);
				}
				@Override
				public void configure(HttpSecurity http) {
					csrf.applyShopifyConfig(http);
				}

			});
			
			http.authorizeRequests()
					.anyRequest().permitAll().and()
				.requiresChannel()
					.anyRequest()
						.requiresInsecure();
		}
		
		private CsrfTokenRepository getCsrfTokenRepo() {
			CookieCsrfTokenRepository repo = new CookieCsrfTokenRepository();
			repo.setCookieHttpOnly(false);
			
			return repo; 
		}
		
	}
	
}
