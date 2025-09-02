package com.ppublica.shopify.app.security.repository;

import com.ppublica.shopify.app.security.ShopifyAccessToken;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Optional;

/*
 * Data saved with OAuth token:
 *  - shop name
 *  - access token
 *  - scope
 *  - date created
 */
public class ShopAccessTokenRepository {
    String GET_ACCESS_TOKEN_BY_SHOP = "SELECT shop, access_token, scope, date_created FROM shopify_oauth_access_tokens WHERE shop = ?";
    String DELETE_ACCESS_TOKEN_BY_SHOP = "DELETE FROM shopify_oauth_access_tokens WHERE shop = ?";
    String INSERT_ACCESS_TOKEN = "INSERT INTO shopify_oauth_access_tokens(shop, access_token, scope, date_created) VALUES(?, ?, ?, ?)";
    String UPDATE_ACCESS_TOKEN = "UPDATE shopify_oauth_access_tokens SET access_token = ?, scope = ?, date_created = ? WHERE shop = ?";

    private final JdbcTemplate template;

    public ShopAccessTokenRepository(JdbcTemplate template) {
        this.template = template;
    }

    public Optional<ShopifyAccessTokenEntity> accessTokenForShop(String shop) {
        try {
            return Optional.ofNullable(template.queryForObject(GET_ACCESS_TOKEN_BY_SHOP, new OAuthAccessTokenRowMapper(), shop));

        } catch(EmptyResultDataAccessException ex) {
            return Optional.empty();
        }
    }

    public long saveAccessTokenForShop(ShopifyAccessTokenEntity accessTokenEntity) {
        KeyHolder keyHolder = new GeneratedKeyHolder();

        template.update(connection -> {
            PreparedStatement ps = connection.prepareStatement(INSERT_ACCESS_TOKEN, Statement.RETURN_GENERATED_KEYS);
            ps.setString(1, accessTokenEntity.shop());
            ps.setString(2, accessTokenEntity.access_token());
            ps.setString(3, accessTokenEntity.scope());
            ps.setTimestamp(4, Timestamp.valueOf(accessTokenEntity.date_created()));
            return ps;
        }, keyHolder);

        Number key = keyHolder.getKey();
        if(key == null) {
            throw new RepositoryException("Error saving access token");
        }

        return keyHolder.getKey().longValue();

    }


    public void deleteAccessToken(String shop) {
        template.update(DELETE_ACCESS_TOKEN_BY_SHOP, shop);
    }



}
