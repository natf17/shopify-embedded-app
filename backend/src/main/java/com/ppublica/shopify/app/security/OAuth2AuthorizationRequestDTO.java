package com.ppublica.shopify.app.security;

import java.util.Map;
import java.util.Set;

/*
 * All the basic components of OAuth2AuthorizationRequest are mirrored here.
 * Custom parameters are stored separately, not in a map of parameters or attributes.
 */
public class OAuth2AuthorizationRequestDTO {

    private String authorizationUri;
    private String clientId;
    private String redirectUri;
    private Set<String> scopes;
    private String state;
    private String authorizationRequestUri;

    public String getAuthorizationUri() {
        return this.authorizationUri;
    }

    public void setAuthorizationUri(String authorizationUri) {
        this.authorizationUri = authorizationUri;
    }

    public String getClientId() {
        return this.clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public String getState() {
        return this.state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getAuthorizationRequestUri() {
        return this.authorizationRequestUri;
    }

    public void setAuthorizationRequestUri(String authorizationRequestUri) {
        this.authorizationRequestUri = authorizationRequestUri;
    }


    public static class Builder {
        private String authorizationUri;
        private String clientId;
        private String redirectUri;
        private Set<String> scopes;
        private String state;
        private String authorizationRequestUri;
        private String registrationId;



        public Builder authorizationUri(String authorizationUri) {
            this.authorizationUri = authorizationUri;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder scopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder authorizationRequestUri(String authorizationRequestUri) {
            this.authorizationRequestUri = authorizationRequestUri;
            return this;
        }

        public Builder registrationId(String registrationId) {
            this.state = state;
            return this;
        }

        public OAuth2AuthorizationRequestDTO build() {
            OAuth2AuthorizationRequestDTO dto = new OAuth2AuthorizationRequestDTO();

            if(isNull(this.authorizationUri) || isNull(this.clientId) || isNull(this.redirectUri) || isNull(this.scopes)
                    || isNull(this.state) || isNull(this.authorizationRequestUri)) {
                throw new NullPointerException();
            }

            dto.authorizationUri = this.authorizationUri;
            dto.clientId = this.clientId;
            dto.redirectUri = this.redirectUri;
            dto.scopes = this.scopes;
            dto.state = this.state;
            dto.authorizationRequestUri = this.authorizationRequestUri;

            return dto;

        }

        private boolean isNull(Object obj) {
            return obj == null;
        }
    }


}
