package com.ppublica.shopify.security.service;

import javax.sql.DataSource;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.ppublica.shopify.TestDataSource;
import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configuration.SecurityBeansConfig;
import com.ppublica.shopify.security.configuration.ShopifyPaths;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@TestPropertySource("classpath:test-application.properties")
@WebAppConfiguration
public class ShopifyBeansUtilsTests {
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyBeansUtils.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	
	@Autowired
	ApplicationContext ac;
	
	ShopifyBeansUtils utils = new ShopifyBeansUtils();
	HttpSecurityBuilder<?> builder;
	
	@Before
	public void setup() {
		HttpSecurityBuilder<?> mock = mock(HttpSecurityBuilder.class);
		doReturn(ac).when(mock).getSharedObject(ApplicationContext.class);
		
		this.builder = mock;
	}
	
	@Test
	public void getRequestResolverFindsBean() {
		OAuth2AuthorizationRequestResolver res = ShopifyBeansUtils.getRequestResolver(builder);
		Assert.assertNotNull(res);
		
	}
	
	@Test
	public void getUserServiceFindsBean() {
		OAuth2UserService<OAuth2UserRequest, OAuth2User> userService = ShopifyBeansUtils.getUserService(builder);
		Assert.assertNotNull(userService);
		
	}
	
	@Test
	public void getSuccessHandlerFindsBean() {
		AuthenticationSuccessHandler res = ShopifyBeansUtils.getSuccessHandler(builder);
		Assert.assertNotNull(res);
		
	}
	
	@Test
	public void getShopifyVerificationStrategyFindsBean() {
		ShopifyVerificationStrategy res = ShopifyBeansUtils.getShopifyVerificationStrategy(builder);
		Assert.assertNotNull(res);
		
	}
	
	@Test
	public void getAuthorizedClientServiceFindsBean() {
		OAuth2AuthorizedClientService res = ShopifyBeansUtils.getAuthorizedClientService(builder);
		Assert.assertNotNull(res);
		
	}
	
	@Test
	public void getJacksonConverterFindsBean() {
		MappingJackson2HttpMessageConverter res = ShopifyBeansUtils.getJacksonConverter(builder);
		Assert.assertNotNull(res);
		
	}
	
	@Test
	public void getShopifyPathsFindsBean() {
		ShopifyPaths res = ShopifyBeansUtils.getShopifyPaths(builder);
		Assert.assertNotNull(res);
		
	}
	
	@EnableWebMvc
	@Configuration
	@Import(SecurityBeansConfig.class)
	static class WebMvcConfig implements WebMvcConfigurer {
		
		@Bean
		TestDataSource testDataSource() {
			return new TestDataSource("shopifysecuritytest");
		}
		
		@Bean
		public JdbcTemplate getJdbcTemplate(CipherPassword cP, TestDataSource tds) {
			DataSource dataSource = tds;
			JdbcTemplate template = new JdbcTemplate(dataSource);
			return template;
		}
		
		@Bean
		public MappingJackson2HttpMessageConverter getMappingJackson2HttpMessageConverter() {
			return new MappingJackson2HttpMessageConverter();
		}
		
	}

}
