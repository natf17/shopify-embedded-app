package com.ppublica.shopify.security.configurer.delegates;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;

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
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.ppublica.shopify.HttpsRequestPostProcessor;
import com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@TestPropertySource("classpath:test-application.properties")
@WebAppConfiguration
public class ShopifyChannelSecurityTests {
	private HttpsRequestPostProcessor httpsPostProcessor = new HttpsRequestPostProcessor();

	@Autowired
	WebApplicationContext wac;

	@Autowired
	Filter springSecurityFilterChain;
	
	MockMvc mockMvc;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyChannelSecurity.class.getName());
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
	public void replaceInsecureConfigAndRejectHttpRequests() throws Exception {
		this.mockMvc.perform(get("/install/shopify?shop=test.myshopify.com"))
		.andExpect(status().is3xxRedirection())
		.andExpect(redirectedUrlPattern("https://**"))
		.andReturn();
	}
	
	@Test
	public void replaceInsecureConfigAndAcceptHttpRequests() throws Exception {
		this.mockMvc.perform(get("/install/shopify?shop=test.myshopify.com").with(httpsPostProcessor))
		.andExpect(status().is4xxClientError())
		.andReturn();
	}
	
	@EnableWebSecurity
	static class RequiresInsecureSecurityConfig extends WebSecurityConfigurerAdapter {
		ShopifyChannelSecurity channel = new ShopifyChannelSecurity();
		// disable defaults to prevent configurer in spring.factories from being applied
		public RequiresInsecureSecurityConfig() {
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
					channel.applyShopifyInit(http);
				}
				@Override
				public void configure(HttpSecurity http) {
					channel.applyShopifyConfig(http);
				}

			});
			
			http.authorizeRequests()
					.anyRequest().authenticated().and()
				.requiresChannel();
		}
	}

}
