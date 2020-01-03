package com.ppublica.shopify.security.converter;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;


/**
 * A custom converter to process the Shopify token response. Although identical to OAuth2AccessTokenResponseConverter, 
 * this converter does not fail if "token_type" is not provided. It defaults to "bearer". It also processes the 
 * scope string Shopify sends back, since it's delimited by "," and not " ".
 * 
 * <p>Also, since Shopify doesn't send back any expiration info, the default is that it'll expire in 1 year</p>
 * 
 * @author N F
 * @see org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
 */
public class ShopifyOAuth2AccessTokenResponseConverter implements Converter<Map<String, String>, OAuth2AccessTokenResponse>{
	private long expiresInSeconds = 31536000L;

	private static final Set<String> TOKEN_RESPONSE_PARAMETER_NAMES = Stream.of(
			OAuth2ParameterNames.ACCESS_TOKEN,
			OAuth2ParameterNames.TOKEN_TYPE,
			OAuth2ParameterNames.EXPIRES_IN,
			OAuth2ParameterNames.REFRESH_TOKEN,
			OAuth2ParameterNames.SCOPE).collect(Collectors.toSet());

	@Override
	public OAuth2AccessTokenResponse convert(Map<String, String> tokenResponseParameters) {
		String accessToken = tokenResponseParameters.get(OAuth2ParameterNames.ACCESS_TOKEN);

		OAuth2AccessToken.TokenType accessTokenType = null;
		if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(
				tokenResponseParameters.get(OAuth2ParameterNames.TOKEN_TYPE))) {
			accessTokenType = OAuth2AccessToken.TokenType.BEARER;
		}
		
		if(accessTokenType == null) {
			accessTokenType = OAuth2AccessToken.TokenType.BEARER;
		}

		/* Shopify doesn't send this back...
		long expiresIn = 0;
		if (tokenResponseParameters.containsKey(OAuth2ParameterNames.EXPIRES_IN)) {
			try {
				expiresIn = Long.valueOf(tokenResponseParameters.get(OAuth2ParameterNames.EXPIRES_IN));
			} catch (NumberFormatException ex) { }
		}*/

		Set<String> scopes = Collections.emptySet();
		if (tokenResponseParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
			String scope = tokenResponseParameters.get(OAuth2ParameterNames.SCOPE);
			scopes = Arrays.stream(StringUtils.delimitedListToStringArray(scope, ",")).collect(Collectors.toSet());
		}

		String refreshToken = tokenResponseParameters.get(OAuth2ParameterNames.REFRESH_TOKEN);

		Map<String, Object> additionalParameters = new LinkedHashMap<>();
		tokenResponseParameters.entrySet().stream()
				.filter(e -> !TOKEN_RESPONSE_PARAMETER_NAMES.contains(e.getKey()))
				.forEach(e -> additionalParameters.put(e.getKey(), e.getValue()));

		return OAuth2AccessTokenResponse.withToken(accessToken)
				.expiresIn(expiresInSeconds)
				.tokenType(accessTokenType)
				.scopes(scopes)
				.refreshToken(refreshToken)
				.additionalParameters(additionalParameters)
				.build();
	}
	
}
