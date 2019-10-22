package com.ppublica.shopify.security.configurer;

import javax.servlet.Filter;
import javax.sql.DataSource;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.ppublica.shopify.AppConfig;
import com.ppublica.shopify.TestDataSource;
import com.ppublica.shopify.security.configuration.ShopifyPaths;
import com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@TestPropertySource("classpath:test-application.properties")
@WebAppConfiguration
public class ShopifySecurityConfigurerTests {
	
	private static String LOGIN_ENDPOINT = "/init";
	private static String ANY_INSTALL_PATH = "/install/**";
	private static String FAV_ICON = "/favicon.ico";
	private static String INSTALL_PATH = "/install";
	
	
	@Autowired
	WebApplicationContext wac;
	
	@Autowired
	ShopifyPaths shopifyPaths;
	
	@Autowired
	Filter springSecurityFilterChain;
	
	@Autowired
	private ShopifyHttpSessionOAuth2AuthorizationRequestRepository authorizationRequestRepository;

	
	MockMvc mockMvc;

	@Before
	public void setup() {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.apply(springSecurity(springSecurityFilterChain))
				.build();
		
		LOGIN_ENDPOINT = shopifyPaths.getLoginEndpoint();
		ANY_INSTALL_PATH = shopifyPaths.getAnyInstallPath();
		INSTALL_PATH = shopifyPaths.getInstallPath() + "/shopify";
	}
	
	/*
	 * Should redirect if the request doesn't come from Shopify and no shop parameter is included
	 */
	@Test
	public void redirectWhenRequestShopParamNotPresent() throws Exception {
		this.mockMvc.perform(get(INSTALL_PATH).secure(true))
			.andExpect(redirectedUrlPattern("/**" + LOGIN_ENDPOINT))
			.andReturn();
		
	}

	/*
	 * Should provide redirection urls for JS if the request doesn't come from Shopify but a shop parameter is included
	 */
	@Test
	public void whenShopParamPresentThenJSRedirect() throws Exception {
	
		MvcResult result = this.mockMvc.perform(get(INSTALL_PATH + "?shop=test.myshopify.com").secure(true))
					//.andExpect(content().string(containsString("var redirectFromParentPath = 'https://test.myshopify.com/admin/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					//.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andReturn();
		
		System.out.println(result.getResponse().getContentAsString());
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
		@Autowired
	    Environment env;
		
		@Bean
		public JdbcTemplate getJdbcTemplate() {
			System.out.println("printing value:" + env.getProperty("ppublica.shopify.client.client_id"));
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

