package com.ppublica.shopify.security.filters;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doNothing;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;

import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;


public class UninstallFilterTests {
	
	ShopifyVerificationStrategy verificationStrategy;
	OAuth2AuthorizedClientService clientService;
	HttpMessageConverter<Object> converter;
	
	@SuppressWarnings("unchecked")
	@Before
	public void setup() {
		verificationStrategy = mock(ShopifyVerificationStrategy.class);
		clientService = mock(OAuth2AuthorizedClientService.class);
		converter = mock(HttpMessageConverter.class);
	}
	
	@Test
	public void doFilterWhenUriNotMatchThenNextFilter() throws Exception {
		String uninstallUri = "/other";
		
		UninstallFilter filter = spy(new UninstallFilter("/uninstallUri", verificationStrategy, clientService, converter));
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uninstallUri);
		request.setServletPath(uninstallUri);
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(verificationStrategy, never()).isHeaderShopifyRequest(any(), any());
		verify(filter, never()).doUninstall(any(), any());

	
	}
	
	@Test
	public void doFilterWhenUriMatchesThenInvokeVerificationStrategy() throws Exception {
		String uninstallUri = "/other/shopify";
		
		UninstallFilter filter = spy(new UninstallFilter(uninstallUri, verificationStrategy, clientService, converter));
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uninstallUri);
		request.setServletPath(uninstallUri);
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(verificationStrategy, times(1)).isHeaderShopifyRequest(any(), any());
		
	}
	
	@Test
	public void doFilterWhenVerificationStrategyTrueThenUninstall() throws Exception {
		String uninstallUri = "/other/shopify";
		doReturn(true).when(verificationStrategy).isHeaderShopifyRequest(any(), any());
		UninstallFilter filter = spy(new UninstallFilter(uninstallUri, verificationStrategy, clientService, converter));
		doNothing().when(filter).doUninstall(any(), any());
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uninstallUri);
		request.setServletPath(uninstallUri);
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(verificationStrategy, times(1)).isHeaderShopifyRequest(any(), any());
		verify(filter, times(1)).doUninstall(any(), any());

	}
	
	@Test
	public void doFilterWhenVerificationStrategyFalseThenUninstallFailure() throws Exception {
		String uninstallUri = "/other/shopify";
		doReturn(false).when(verificationStrategy).isHeaderShopifyRequest(any(), any());
		UninstallFilter filter = spy(new UninstallFilter(uninstallUri, verificationStrategy, clientService, converter));
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uninstallUri);
		request.setServletPath(uninstallUri);
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(verificationStrategy, times(1)).isHeaderShopifyRequest(any(), any());
		verify(filter, never()).doUninstall(any(), any());
		verify(filter, times(1)).uninstallFailure(any(), any());

	}
	
	//body null doUninstall calls uninstall failure
	@Test
	public void doUninstallWhenRequestBodyNullThenCallsUninstallFailure() throws Exception {
		byte[] nullBody = new byte[]{};
		
		
		String uninstallUri = "/other/shopify";
		UninstallFilter filter = spy(new UninstallFilter(uninstallUri, verificationStrategy, clientService, converter));
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uninstallUri);
		request.setContent(nullBody);
		MockHttpServletResponse response = new MockHttpServletResponse();


		filter.doUninstall(request, response);
		verify(filter, times(1)).uninstallFailure(any(), any());

	}
	// bad body doUninstall calls uninstall failure
	@Test
	public void doUninstallWhenRequestBadBodyThenCallsUninstallFailure() throws Exception {
		String badBody = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\"\n" +
				"}\n";
		
		
		String uninstallUri = "/other/shopify";
		UninstallFilter filter = spy(new UninstallFilter(uninstallUri, verificationStrategy, clientService, converter));
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uninstallUri);
		request.setContent(badBody.getBytes());
		MockHttpServletResponse response = new MockHttpServletResponse();


		filter.doUninstall(request, response);
		verify(filter, times(1)).uninstallFailure(any(), any());

	}
	// missing shop doUinstall calls uninstall failure
	@Test
	public void doUninstallWhenRequestMissingShopThenCallsUninstallFailure() throws Exception {
		String bodyMissingShop = "{\n" +
				"	\"shop_id\": \"1234\"\n" +
				"}\n";
		
		
		String uninstallUri = "/other/shopify";
		UninstallFilter filter = spy(new UninstallFilter(uninstallUri, verificationStrategy, clientService, converter));
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uninstallUri);
		request.setContent(bodyMissingShop.getBytes());
		MockHttpServletResponse response = new MockHttpServletResponse();


		filter.doUninstall(request, response);
		verify(filter, times(1)).uninstallFailure(any(), any());

	}
	// upon sucess doUninstall removes using clientservice and calls uninstall success
	@Test
	public void doUninstallWhenValidBodyThenRemovesStoreAndCallsUninstallSuccess() throws Exception {
		String validBody = "{\n" +
				"	\"shop_id\": \"1234\",\n" +
				"	\"shop_domain\": \"domain\"\n" +
				"}\n";
		
		
		String uninstallUri = "/other/shopify";
		UninstallFilter filter = spy(new UninstallFilter(uninstallUri, verificationStrategy, clientService, new MappingJackson2HttpMessageConverter()));
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uninstallUri);
		request.setContent(validBody.getBytes());
		MockHttpServletResponse response = new MockHttpServletResponse();


		filter.doUninstall(request, response);
		verify(filter, never()).uninstallFailure(any(), any());
		verify(clientService, times(1)).removeAuthorizedClient(any(), any());
		verify(filter, times(1)).uninstallSuccess(any(), any());

	}
	
	// uninstallsuccess sets 200 status code
	@Test
	public void uninstallSuccessSets200() throws Exception {

		String uninstallUri = "/other/shopify";
		UninstallFilter filter = new UninstallFilter(uninstallUri, verificationStrategy, clientService, converter);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uninstallUri);

		MockHttpServletResponse response = new MockHttpServletResponse();
		
		filter.uninstallSuccess(request, response);

		Assert.assertEquals(200, response.getStatus());

	}
	
	// uninstallfailure sends error 403
	@Test
	public void uninstallSuccessSets403() throws Exception {

		String uninstallUri = "/other/shopify";
		UninstallFilter filter = new UninstallFilter(uninstallUri, verificationStrategy, clientService, converter);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uninstallUri);

		MockHttpServletResponse response = new MockHttpServletResponse();
		
		filter.uninstallFailure(request, response);

		Assert.assertEquals(403, response.getStatus());

	}

}
