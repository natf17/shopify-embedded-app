package com.ppublica.shopify.app.security;

import java.util.List;
import java.util.TreeMap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

public class ShopifyOriginVerifierTest {

    private static String secret;

    @BeforeAll
    static void init() {
        secret = System.getenv("app_client_secret");
        Logger logger = (Logger) LoggerFactory.getLogger("com.ppublica.shopify.app.security.ShopifyOriginVerifierTest");
        logger.setLevel(Level.DEBUG);
    }


    @Test
    void toQueryString_shouldReturnQueryString_whenFullMap() {
        ShopifyOriginVerifier verifier = new ShopifyOriginVerifier("message");
        TreeMap<String, List<String>> queryStringMap = new TreeMap<>();
        queryStringMap.put("code", List.of("0907"));
        queryStringMap.put("shop", List.of("shop.myshopify.com"));
        queryStringMap.put("state", List.of("0.63"));
        queryStringMap.put("timestamp", List.of("13"));

        assertEquals("code=0907&shop=shop.myshopify.com&state=0.63&timestamp=13", verifier.toQueryString(queryStringMap));

    }

    @Test
    void comesFromShopify_shouldReturnTrue_whenValidString() {
        String queryString = "embedded=1&hmac=dcf9f09c90a40b2e87d89c5a99dca6284b54935188d8f34fe2e4d7eba942d213&host=YWRtaW4uc2hvcGlmeS5jb20vc3RvcmUvc2hjbGl0ZXN0&id_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczpcL1wvc2hjbGl0ZXN0Lm15c2hvcGlmeS5jb21cL2FkbWluIiwiZGVzdCI6Imh0dHBzOlwvXC9zaGNsaXRlc3QubXlzaG9waWZ5LmNvbSIsImF1ZCI6IjY3MzlhOTk5MTc0OTllYWM5OTRjMDdjNmE2OTY5Njg4Iiwic3ViIjoiMTM1MzcxOTE1NjMyIiwiZXhwIjoxNzU4MzQ2ODg4LCJuYmYiOjE3NTgzNDY4MjgsImlhdCI6MTc1ODM0NjgyOCwianRpIjoiZmEyNWFjN2MtNzU1Yi00ODFhLWJmY2EtMzc5YWE1ODA5MmRiIiwic2lkIjoiNDZkOWRlZGItMjNhNy00MGQ3LTlkNzItN2Y2YmU4NmNjYjgzIiwic2lnIjoiNzQwMDU1Mzg3NWFhNTQ4ZDkzZjVmMDZiNmU0ODhjMjBmYzhjODAxOTU1NTgwMjBhMTA2MWFkZTk1MmRkMDJkOSJ9.Iwu8tBpVKN15rYfF8nfFMmPntqfnO5TdsU3gZbap6qw&locale=en&session=7230fae8316a47c5da0113753b88d2d593780297dcc0352285d7c50a012702e7&shop=shclitest.myshopify.com&timestamp=1758346828";
        ShopifyOriginVerifier verifier = new ShopifyOriginVerifier(secret);

        assertTrue(verifier.comesFromShopify(queryString));

    }

}
