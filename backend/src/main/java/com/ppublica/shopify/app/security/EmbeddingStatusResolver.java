package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;

import static com.ppublica.shopify.app.security.ShopifyUtils.EMBEDDED_QUERY_PARAM;

public class EmbeddingStatusResolver {

    public boolean isEmbedded(HttpServletRequest request) {
        return hasActiveEmbeddedParameter(request);
    }

    public boolean hasActiveEmbeddedParameter(HttpServletRequest request) {
        String isEmbedded = request.getParameter(EMBEDDED_QUERY_PARAM);

        if(isEmbedded == null || isEmbedded.isEmpty() || isEmbedded.equals("0")) {
            return false;
        }

        // then it must equal 1
        return true;
    }
}
