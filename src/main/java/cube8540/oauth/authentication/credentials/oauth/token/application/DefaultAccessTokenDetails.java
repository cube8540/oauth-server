package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2RefreshTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class DefaultAccessTokenDetails implements OAuth2AccessTokenDetails {

    private static final String TOKEN_TYPE = "Bearer";

    private final String tokenValue;
    private final OAuth2ClientId clientId;
    private final Set<OAuth2ScopeId> scopeId;
    private final String tokenType;
    private final String username;
    private final Map<String, String> additionalInformation;
    private final LocalDateTime expiration;
    private final long expiresIn;
    private final OAuth2RefreshTokenDetails refreshTokenDetails;
    private final boolean isExpired;

    public DefaultAccessTokenDetails(OAuth2AuthorizedAccessToken accessToken) {
        this.tokenValue = accessToken.getTokenId().getValue();
        this.clientId = accessToken.getClient();
        this.scopeId = Collections.unmodifiableSet(accessToken.getScope());
        this.username = accessToken.getEmail().getValue();
        this.expiration = accessToken.getExpiration();
        this.expiresIn = accessToken.expiresIn();
        this.isExpired = accessToken.isExpired();
        this.refreshTokenDetails = accessToken.getRefreshToken() != null ?
                new DefaultRefreshTokenDetails(accessToken.getRefreshToken()) : null;
        this.tokenType = TOKEN_TYPE;
        if (accessToken.getAdditionalInformation() != null) {
            this.additionalInformation = Collections.unmodifiableMap(accessToken.getAdditionalInformation());
        } else {
            this.additionalInformation = null;
        }
    }

    @Override
    public OAuth2ClientId clientId() {
        return clientId;
    }

    @Override
    public Set<OAuth2ScopeId> scope() {
        return scopeId;
    }

    @Override
    public String tokenType() {
        return tokenType;
    }

    @Override
    public String username() {
        return username;
    }

    @Override
    public OAuth2RefreshTokenDetails refreshToken() {
        return refreshTokenDetails;
    }

    @Override
    public Map<String, String> additionalInformation() {
        return additionalInformation;
    }

    @Override
    public String tokenValue() {
        return tokenValue;
    }

    @Override
    public LocalDateTime expiration() {
        return expiration;
    }

    @Override
    public boolean isExpired() {
        return isExpired;
    }

    @Override
    public int expiresIn() {
        return Long.valueOf(expiresIn).intValue();
    }
}
