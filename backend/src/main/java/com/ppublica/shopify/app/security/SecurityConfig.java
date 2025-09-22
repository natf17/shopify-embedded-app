package com.ppublica.shopify.app.security;

import com.ppublica.shopify.app.security.repository.ShopAccessTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.client.RestClient;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Value("${ppublica.shopify.app.oauth.client-secret}")
    private String clientSecret;

    @Value("${ppublica.shopify.app.oauth.client-id}")
    private String clientId;

    @Value("${ppublica.shopify.app.path-requiring-shopify-origin-verification:/**}")
    private String pathRequiringShopifyOriginVerification;

    private String clientRegistrationId = "shopify";

    private String authorizationRequestBaseUri = "/app";
    private String pathToApp = authorizationRequestBaseUri + "/" + clientRegistrationId;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ShopifyRequestAuthenticationFilter shopifyRequestAuthenticationFilter,
                                                   ClientRegistrationRepository clientRegistrationRepo,
                                                   AuthenticationManager authenticationManager,
                                                   AccessTokenService accessTokenService) throws Exception {
        http.authorizeHttpRequests( authorize -> authorize
                .anyRequest().authenticated()
        )
            .oauth2Client(oauth2Client -> oauth2Client
                        .authorizationCodeGrant(authCodeGrant -> authCodeGrant
                                .authorizationRequestResolver(authorizationRequestResolver(clientRegistrationRepo))
                                .authorizationRequestRepository(authorizationRequestRepository())
                                .authorizationRedirectStrategy(authorizationRedirectStrategy())
                        )
                    .authorizedClientService(accessTokenService)
            )
            .addFilterBefore(shopifyRequestAuthenticationFilter, OAuth2AuthorizationRequestRedirectFilter.class)
            .requestCache(requestCache -> requestCache.requestCache(shopifyAppRequestCache()))
            .authenticationManager(authenticationManager) // spring internals will use this instead of authentication manager builder
            .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));

        return http.build();

    }

    @Bean
    public ShopifyAppRequestCache shopifyAppRequestCache() {
        return new ShopifyAppRequestCache(pathToApp, clientId);
    }

    @Bean
    public SecureCookieSerializer cookieSerializer() {
        return new SecureCookieSerializer(clientSecret, clientRegistrationId);
    }

    @Bean
    public CookieOAuth2AuthorizationRequestRepository authorizationRequestRepository() {
        return new CookieOAuth2AuthorizationRequestRepository(cookieSerializer());
    }

    @Bean
    public ShopifyAuthorizationRequestRedirectStrategy authorizationRedirectStrategy() {
        return new ShopifyAuthorizationRequestRedirectStrategy(clientId);
    }

    @Bean
    public ShopifyOriginVerifier shopifyOriginVerifier() {
        return new ShopifyOriginVerifier(clientSecret);
    }


    @Bean
    public ShopifyRequestAuthenticationFilter shopifyRequestAuthenticationFilter(AuthenticationManager authenticationManager, ShopifyOriginVerifier shopifyOriginVerifier) {
        return new ShopifyRequestAuthenticationFilter(authenticationManager, PathPatternRequestMatcher.pathPattern(pathRequiringShopifyOriginVerification));
    }

    // becomes the parent/global AuthenticationManager: see AuthenticationConfiguration/HttpSecurityConfiguration
    @Bean
    public AuthenticationManager authenticationManager(ShopifyRequestAuthenticationProvider shopifyRequestAuthenticationProvider, ShopifyOAuth2AuthorizationCodeAuthenticationProvider shopifyOAuth2AuthorizationCodeAuthenticationProvider) throws Exception {
        List<AuthenticationProvider> providers = List.of(
            shopifyRequestAuthenticationProvider,
            shopifyOAuth2AuthorizationCodeAuthenticationProvider);
        return new ProviderManager(providers);
    }

    @Bean
    public ShopifyRequestAuthenticationProvider shopifyRequestAuthenticationProvider(AccessTokenService accessTokenService, ShopifyOriginVerifier shopifyOriginVerifier) {
        return new ShopifyRequestAuthenticationProvider(accessTokenService, shopifyOriginVerifier);
    }

    @Bean
    public ShopifyOAuth2AuthorizationCodeAuthenticationProvider shopifyOAuth2AuthorizationCodeAuthenticationProvider() {
        OAuth2AccessTokenResponseHttpMessageConverter accessTokenResponseHttpMessageConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
        accessTokenResponseHttpMessageConverter.setAccessTokenResponseConverter(new ShopifyMapOAuth2AccessTokenResponseConverter());

        RestClient newRestClient = RestClient.builder().configureMessageConverters(clientBuilder -> {
            clientBuilder.customMessageConverter(new FormHttpMessageConverter());
            clientBuilder.customMessageConverter(accessTokenResponseHttpMessageConverter);
        }).build();

        RestClientAuthorizationCodeTokenResponseClient authCodeTokenResponseClient = new RestClientAuthorizationCodeTokenResponseClient();
        authCodeTokenResponseClient.setRestClient(newRestClient);

        return new ShopifyOAuth2AuthorizationCodeAuthenticationProvider(authCodeTokenResponseClient);
    }

    @Bean
    public AccessTokenService accessTokenService(ShopAccessTokenRepository shopAccessTokenRepository, ClientRegistrationRepository clientRegistrationRepo) {
        return new AccessTokenService(shopAccessTokenRepository, clientRegistrationRepo, clientRegistrationId);
    }

    @Bean
    public ShopAccessTokenRepository shopAccessTokenRepository(JdbcTemplate template) {
        return new ShopAccessTokenRepository(template);
    }

    // a request to /app/shopify will start the oauth flow -> the client registration with
    // id "shopify" will be matched
    private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        return new ShopifyOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, authorizationRequestBaseUri, clientRegistrationId);

    }



}
