package com.ppublica.shopify.security.configurer;

import javax.servlet.Filter;
import javax.sql.DataSource;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.ppublica.shopify.AppConfig;
import com.ppublica.shopify.TestDataSource;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class ShopifySecurityConfigurerTests {
	
	private static final String LOGIN_ENDPOINT = ShopifySecurityConfigurer.LOGIN_ENDPOINT;
	private static final String ANY_INSTALL_PATH = ShopifySecurityConfigurer.ANY_INSTALL_PATH;
	private static final String FAV_ICON = "/favicon.ico";
	private static final String INSTALL_PATH = ShopifySecurityConfigurer.INSTALL_PATH + "/shopify";
	
	
	@Autowired
	WebApplicationContext wac;
	
	@Autowired
	Filter springSecurityFilterChain;
	
	MockMvc mockMvc;

	@Before
	public void setup() {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.apply(springSecurity(springSecurityFilterChain))
				.build();
	}
	
	@Test
	public void redirectWhenRequestShopParamNotPresent() throws Exception {
		this.mockMvc.perform(get(INSTALL_PATH).secure(true))
			.andExpect(redirectedUrlPattern("/**" + LOGIN_ENDPOINT))
			.andReturn();
		
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
						.requiresSecure().and()
					.oauth2Login();
		}
	}
	
	@EnableWebMvc
	@Configuration
	@Import(AppConfig.class)
	static class WebMvcConfig implements WebMvcConfigurer {
		@Bean
		public JdbcTemplate getJdbcTemplate() {
			DataSource dataSource = new TestDataSource("shopifysecuritytest");
			JdbcTemplate template = new JdbcTemplate(dataSource);
			
			return template;
		}
		
		@Bean
		public MappingJackson2HttpMessageConverter getMappingJackson2HttpMessageConverter() {
			return new MappingJackson2HttpMessageConverter();
		}
	}
	
	
	
	
}

