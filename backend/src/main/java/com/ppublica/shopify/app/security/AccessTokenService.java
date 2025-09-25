package com.ppublica.shopify.app.security;

import com.ppublica.shopify.app.security.repository.ShopAccessTokenRepository;
import com.ppublica.shopify.app.security.repository.ShopifyAccessTokenEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import java.util.Optional;

public class AccessTokenService implements OAuth2AuthorizedClientService {
    private static final Logger log = LoggerFactory.getLogger(AccessTokenService.class);
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
        log.debug("Loading authorized client");
        if(!clientRegistrationId.equals(shopifyRegistrationId)) {
            throw new ShopifySecurityException();
        }

        Optional<ShopifyAccessTokenEntity> accessTokenEntity = shopAccessTokenRepository.accessTokenForShop(principalName);
        if(accessTokenEntity.isEmpty()) {
            log.debug("Returning null; no token found");
            return null;
        }

        return (T) entityMapper.toOAuth2AuthorizedClient(shopifyClientRegistration, principalName, accessTokenEntity.get());

    }

    // called by OAuth2AuthorizationCodeGrantFilter to save the request
    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        log.debug("Saving an authorized client (a token)");

        ShopifyAccessTokenEntity accessTokenEntity = entityMapper.toShopifyAccessTokenEntity(authorizedClient);

        log.debug("It was converted to ShopifyAccessTokenEntity: {}", accessTokenEntity);

        shopAccessTokenRepository.saveAccessTokenForShop(accessTokenEntity);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        log.debug("Deleting an authorized client (a token)");

        if(!clientRegistrationId.equals(shopifyRegistrationId)) {
            throw new ShopifySecurityException();
        }

        shopAccessTokenRepository.deleteAccessToken(principalName);
    }
}
