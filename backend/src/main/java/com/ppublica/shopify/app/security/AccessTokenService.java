package com.ppublica.shopify.app.security;

import com.ppublica.shopify.app.security.repository.ShopAccessTokenRepository;
import com.ppublica.shopify.app.security.repository.ShopifyAccessTokenEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import java.util.Optional;

public class AccessTokenService implements OAuth2AuthorizedClientService {
    private final ShopAccessTokenRepository shopAccessTokenRepository;
    private final ShopifyAccessTokenEntityMapper entityMapper = new ShopifyAccessTokenEntityMapper();
    private final ClientRegistration shopifyClientRegistration;
    private final String shopifyRegistrationId;

    public AccessTokenService(ShopAccessTokenRepository shopAccessTokenRepository, ClientRegistrationRepository clientRegistrationRepository, String shopifyRegistrationId) {
        this.shopAccessTokenRepository = shopAccessTokenRepository;
        this.shopifyClientRegistration = clientRegistrationRepository.findByRegistrationId(shopifyRegistrationId);
        this.shopifyRegistrationId = shopifyRegistrationId;
    }

    // called when authenticating
    public Optional<ShopifyAccessToken> accessTokenForShop(String shop) {
        Optional<ShopifyAccessTokenEntity> accessTokenEntity = shopAccessTokenRepository.accessTokenForShop(shop);
        if(accessTokenEntity.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(entityMapper.toShopifyAccessToken(accessTokenEntity.get()));
    }

    public void deleteToken(String shop) {
        shopAccessTokenRepository.deleteAccessToken(shop);
    }


    @Override
    @SuppressWarnings("unchecked")
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        if(!clientRegistrationId.equals(shopifyRegistrationId)) {
            throw new ShopifySecurityException();
        }

        Optional<ShopifyAccessTokenEntity> accessTokenEntity = shopAccessTokenRepository.accessTokenForShop(principalName);
        if(accessTokenEntity.isEmpty()) {
            return null;
        }

        return (T) entityMapper.toOAuth2AuthorizedClient(shopifyClientRegistration, principalName, accessTokenEntity.get());

    }

    // called by OAuth2AuthorizationCodeGrantFilter to save the request
    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        shopAccessTokenRepository.saveAccessTokenForShop(entityMapper.toShopifyAccessTokenEntity(authorizedClient));
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        if(!clientRegistrationId.equals(shopifyRegistrationId)) {
            throw new ShopifySecurityException();
        }

        shopAccessTokenRepository.deleteAccessToken(principalName);
    }
}
