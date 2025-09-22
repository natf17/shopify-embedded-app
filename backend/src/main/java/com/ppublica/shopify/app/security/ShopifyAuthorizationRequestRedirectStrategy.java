package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;

public class ShopifyAuthorizationRequestRedirectStrategy implements RedirectStrategy {
    private static final Logger log = LoggerFactory.getLogger(ShopifyAuthorizationRequestRedirectStrategy.class);
    private final DefaultRedirectStrategy defaultRedirectStrategy = new DefaultRedirectStrategy();
    private final String shopifyApiKey;

    public ShopifyAuthorizationRequestRedirectStrategy(String shopifyApiKey) {
        this.shopifyApiKey = shopifyApiKey;
    }

    @Override
    public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
        log.debug("Redirecting...");
        if (!ShopifyUtils.isEmbedded(request)) {
            log.debug("The app is not embedded... redirecting to " + url);
            defaultRedirectStrategy.sendRedirect(request, response, url);
            return;
        }
        log.debug("The app is embedded...");
        renderShopifyAppBridgeRedirectPage(request, response, url);

    }



    protected void renderShopifyAppBridgeRedirectPage(HttpServletRequest request, HttpServletResponse response, String url) {
        String redirectUrl = request.getRequestURL().toString();
        log.debug("Setting the following variables in the HTML returned: shopify-api-key = {}, redirectUri = {}", shopifyApiKey, redirectUrl);

        response.setContentType("text/html;charset=UTF-8");

        try {
            response.getWriter().write("""
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                          <meta charset="UTF-8">
                          <title>Redirecting</title>
                          <meta name="shopify-api-key" content="%s" />
                          <script src="https://unpkg.com/@shopify/app-bridge@3.7.10/umd/index.js"></script>
                        </head>
                        <body>
                          <script>
                            const params = new URLSearchParams(window.location.search);
                            const shop = params.get('shop');
                            const host = params.get('host');
                            console.log(shop);console.log(host);
                            const apiKey = document.querySelector('meta[name="shopify-api-key"]').content;
                            const redirectUri = "%s";
                            console.log(apiKey);console.log(redirectUri)
                            const AppBridge = window['app-bridge'];
                            console.log(AppBridge);
                            const createApp = AppBridge.default;
                            const app = createApp({ apiKey: apiKey, host: host, forceRedirect: true });
                            
                            const Redirect = AppBridge.actions.Redirect;
                            console.log("Redirecting");
                            console.log(Redirect);
                            Redirect.create(app).dispatch(Redirect.Action.REMOTE, redirectUri);
                          </script>
                        </body>
                        </html>
                    """.formatted(HtmlUtils.htmlEscape(shopifyApiKey), HtmlUtils.htmlEscape(redirectUrl)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

}
