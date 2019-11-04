package com.ppublica.shopify.security.configurer.delegates;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

import javax.servlet.Filter;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
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
public class ShopifyHeadersTests {

	@Autowired
	WebApplicationContext wac;

	@Autowired
	Filter springSecurityFilterChain;
	
	MockMvc mockMvc;
	
	@Before
	public void setup() throws Exception {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.apply(springSecurity(springSecurityFilterChain))
				.build();
	}
	
	@Test
	public void anyRequestXFrameOptionsMissing() throws Exception {
		this.mockMvc.perform(get("/install"))
			.andExpect(header().doesNotExist("X-Frame-Options"))
			.andReturn();
		
	}
	
	@EnableWebSecurity
	static class ApplyCsrfSecurityConfig extends WebSecurityConfigurerAdapter {
		
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
					new ShopifyHeaders().applyShopifyInit(http);
				}
				@Override
				public void configure(HttpSecurity http) {
					new ShopifyHeaders().applyShopifyConfig(http);
				}

			});
			
			http.authorizeRequests()
					.anyRequest().permitAll().and()
				.requiresChannel()
					.anyRequest()
						.requiresInsecure();
		}
		
	}
	
}
