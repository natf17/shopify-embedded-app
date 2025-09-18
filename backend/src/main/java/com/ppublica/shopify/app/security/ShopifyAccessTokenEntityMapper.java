package com.ppublica.shopify.app.security;

import com.ppublica.shopify.app.security.repository.ShopifyAccessTokenEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Set;

public class ShopifyAccessTokenEntityMapper {
    public ShopifyAccessTokenEntity toShopifyAccessTokenEntity(ShopifyAccessToken model) {
        return new ShopifyAccessTokenEntity(model.shop(), model.access_token(), model.scope(), model.date_created());
    }

    public ShopifyAccessToken toShopifyAccessToken(ShopifyAccessTokenEntity entity) {
        return new ShopifyAccessToken(entity.shop(), entity.access_token(), entity.scope(), entity.date_created());
    }

    public OAuth2AuthorizedClient toOAuth2AuthorizedClient(ClientRegistration shopifyClientRegistration, String shop, ShopifyAccessTokenEntity entity) {

        Set<String> scopeSet = ShopifyUtils.convertScope(entity.scope());

        ZoneId zoneId = ZoneId.systemDefault();
        Instant dateCreatedInstant = entity.date_created().atZone(zoneId).toInstant();

        OAuth2AccessToken token = new OAuth2AccessToken(null, entity.access_token(), dateCreatedInstant, null, scopeSet);
        return new OAuth2AuthorizedClient(shopifyClientRegistration, shop, token);
    }

    public ShopifyAccessTokenEntity toShopifyAccessTokenEntity(OAuth2AuthorizedClient authorizedClient) {
        String shop = authorizedClient.getPrincipalName();
        String access_token = authorizedClient.getAccessToken().getTokenValue();
        String scope = ShopifyUtils.convertScope(authorizedClient.getAccessToken().getScopes());
        LocalDateTime dateCreated = LocalDateTime.ofInstant(authorizedClient.getAccessToken().getIssuedAt(), ZoneId.systemDefault());

        return new ShopifyAccessTokenEntity(shop, access_token, scope, dateCreated);
    }
}
