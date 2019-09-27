package com.ppublica.shopify.security.configurer;

import javax.servlet.Filter;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class ShopifySecurityConfigurerTest {
	
	private static final String LOGIN_ENDPOINT = ShopifySecurityConfigurer.LOGIN_ENDPOINT;
	private static final String ANY_INSTALL_PATH = ShopifySecurityConfigurer.ANY_INSTALL_PATH;
	private static final String FAV_ICON = "/favicon.ico";
	private static final String INSTALL_PATH = ShopifySecurityConfigurer.INSTALL_PATH;
	
	
	@Autowired
	WebApplicationContext wac;
	
	@Autowired
	Filter springSecurityFilterChain;
	
	MockMvc mockMvc;

	@Before
	public void setup() {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.addFilters(springSecurityFilterChain)
				.build();
	}
	
	@Test
	public void redirectWhenRequestShopParamNotPresent() throws Exception {
		this.mockMvc.perform(get(INSTALL_PATH))
			.andExpect(redirectedUrlPattern("/**" + LOGIN_ENDPOINT));
		
	}
	
	
	
	
	@EnableWebSecurity
	static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// minimum requirements...
			http.authorizeRequests()
					.mvcMatchers(LOGIN_ENDPOINT).permitAll()
					.mvcMatchers(ANY_INSTALL_PATH).permitAll()
					.mvcMatchers(FAV_ICON).permitAll()
					.anyRequest().authenticated().and()
				.requiresChannel()
					.anyRequest()
						.requiresSecure();
		}
	}
}

