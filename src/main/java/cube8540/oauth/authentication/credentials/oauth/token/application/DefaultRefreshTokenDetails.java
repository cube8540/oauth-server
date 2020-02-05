package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.OAuth2RefreshTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.time.LocalDateTime;

@ToString
@EqualsAndHashCode
public class DefaultRefreshTokenDetails implements OAuth2RefreshTokenDetails {

    private final String tokenValue;
    private final LocalDateTime expiration;
    private final boolean isExpired;
    private final long expires;

    public DefaultRefreshTokenDetails(OAuth2AuthorizedRefreshToken refreshToken) {
        this.tokenValue = refreshToken.getTokenId().getValue();
        this.expiration = refreshToken.getExpiration();
        this.isExpired = refreshToken.isExpired();
        this.expires = refreshToken.expiresIn();
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
        return Long.valueOf(expires).intValue();
    }
}
