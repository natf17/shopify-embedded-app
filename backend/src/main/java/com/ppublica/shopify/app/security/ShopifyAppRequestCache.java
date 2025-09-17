package com.ppublica.shopify.app.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.*;

/*
 * Delegates to HttpSessionRequestCache, but changes the redirectUri of the SavedRequest to always redirect
 * to either the full path url or the embedded app url.
 *
 * This way, OAuth2AuthorizationCodeGrantFilter always finds a SavedRequest in the RequestCache and will always use
 * its redirect uri to redirect after successfully obtaining the access token.
 *
 */
public class ShopifyAppRequestCache implements RequestCache {
    private RequestCache requestCache = new HttpSessionRequestCache();

    private final DefaultRedirectStrategy defaultRedirectStrategy = new DefaultRedirectStrategy();
    private final String pathToAppTemplate;
    private final String pathToEmbeddedAppTemplate;
    private final String clientId;

    private static final String SHOP_PARAM = "shop";
    private static final String HOST_PARAM = "host";
    private static final String HOST_URL = "base64_decoded_host";

    public ShopifyAppRequestCache(String pathToApp, String clientId) {
        this.pathToAppTemplate = pathToApp + "?" + SHOP_PARAM + "={shop}&" + HOST_PARAM + "={host}";
        this.pathToEmbeddedAppTemplate = "https://{base64_decoded_host}/apps/{api_key}/";
        this.clientId = clientId;
    }


    /*
     * Counterintuitively, if the "embedded" parameter is present and equal to 1, then we redirect to the full app url
     * If it's not present or equal to 0, then we redirect to the embedded app url
     *
     * The url parameter received here is chosen by OAuth2AuthorizationCodeGrantFilter and is either the redirect uri from:
     *  - the SavedRequest from RequestCache OR
     *  - authorizationRequest.getRedirectUri()
     */
    public void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if(ShopifyUtils.hasActiveEmbeddedParameter(request)) {
            redirectToFullAppUrl(request, response);
        } else {
            redirectToEmbeddedAppUrl(request, response);
        }
    }

    /*
     * From the Shopify docs:
     *
     * If you redirect to your app URL, then make sure to include the shop and host parameters.
     * Without these parameters, App Bridge can't initialize and your UI can't get a session token.
     */

    public String redirectToFullAppUrl(HttpServletRequest request, HttpServletResponse response) {
        ShopifyHttpRequest req = new ShopifyHttpRequest(request);

        String shop = req.getShop();
        String host = req.getRawHost();

        Map<String, String> vars = Map.of(SHOP_PARAM, shop, HOST_PARAM, host);
        return UriComponentsBuilder.fromUriString(pathToAppTemplate)
                .buildAndExpand(vars)
                .toUriString();

    }

    /*
     * From the Shopify docs:
     *
     * You can construct the embedded app URL manually using the following format:
     * https://{base64_decode(host)}/apps/{api_key}/
     *
     * Note: The host variable is base64-encoded and then the padding characters (=) are removed. Some base64 decoders
     * like Node.js can handle the lack of padding, and others like Python can't handle the lack of padding. As a result,
     * you might need to add padding to the bytes before decoding.
     */
    public String redirectToEmbeddedAppUrl(HttpServletRequest request, HttpServletResponse response) {
        ShopifyHttpRequest req = new ShopifyHttpRequest(request);
        String host = req.getBase64DecodedHost();

        Map<String, String> vars = Map.of("base64_decoded_host", host, "api_key", this.clientId);
        String embeddedAppPath = UriComponentsBuilder.fromUriString(pathToEmbeddedAppTemplate)
                .buildAndExpand(vars)
                .toUriString();

        return embeddedAppPath;
    }

    @Override
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        requestCache.saveRequest(request, response);
    }

    @Override
    public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        String redirectUri;

        if(ShopifyUtils.hasActiveEmbeddedParameter(request)) {
            redirectUri = redirectToFullAppUrl(request, response);
        } else {
            redirectUri = redirectToEmbeddedAppUrl(request, response);
        }

        return new ShopifySavedRequest(redirectUri, savedRequest);
    }

    @Override
    public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
        // none are saved
        return requestCache.getMatchingRequest(request, response);
    }

    @Override
    public void removeRequest(HttpServletRequest request, HttpServletResponse response) {
        requestCache.removeRequest(request, response);
    }

    class ShopifySavedRequest implements SavedRequest {
        private String redirectUrl;
        private SavedRequest delegate;

        public ShopifySavedRequest(String redirectUrl, SavedRequest delegate) {
            this.redirectUrl = redirectUrl;
            this.delegate = delegate;
        }


        @Override
        public String getRedirectUrl() {
            return this.redirectUrl;
        }

        @Override
        public List<Cookie> getCookies() {
            return this.delegate != null ? delegate.getCookies() : List.of();
        }

        @Override
        public String getMethod() {
            return this.delegate != null ? delegate.getMethod() : "";
        }

        @Override
        public List<String> getHeaderValues(String name) {
            return this.delegate != null ? delegate.getHeaderValues(name) : List.of();
        }

        @Override
        public Collection<String> getHeaderNames() {
            return this.delegate != null ? delegate.getHeaderNames() : Collections.emptyList();
        }

        @Override
        public List<Locale> getLocales() {
            return this.delegate != null ? delegate.getLocales() : List.of();
        }

        @Override
        public String[] getParameterValues(String name) {
            return this.delegate != null ? delegate.getParameterValues(name) : new String[]{};
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return this.delegate != null ? delegate.getParameterMap() : Map.of();
        }
    }
}
