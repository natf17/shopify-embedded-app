package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;

public class EmbeddingStatusResolver {

    public boolean isEmbedded(HttpServletRequest request) {
        String isEmbedded = request.getParameter("embedded");

        if(isEmbedded == null || isEmbedded.isEmpty() || isEmbedded.equals("0")) {
            return false;
        }

        // then it must equal 1
        return true;
    }
}
