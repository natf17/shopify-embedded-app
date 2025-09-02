package com.ppublica.shopify.app.security.repository;

import com.ppublica.shopify.app.security.ShopifyAccessToken;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;

public class OAuthAccessTokenRowMapper implements RowMapper<ShopifyAccessTokenEntity> {
    @Override
    public ShopifyAccessTokenEntity mapRow(ResultSet rs, int rowNum) throws SQLException {

        String shop = rs.getString("shop");
        String access_token = rs.getString("access_token");
        String scope = rs.getString("scope");
        LocalDateTime date_created = rs.getTimestamp("date_created").toLocalDateTime();

        return new ShopifyAccessTokenEntity(shop, access_token, scope, date_created);
    }
}
