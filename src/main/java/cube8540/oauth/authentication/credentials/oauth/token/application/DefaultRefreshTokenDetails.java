package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2RefreshTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import lombok.Builder;
import lombok.Value;

import java.time.LocalDateTime;

@Value
@Builder
public class DefaultRefreshTokenDetails implements OAuth2RefreshTokenDetails {

    String tokenValue;

    LocalDateTime expiration;

    boolean isExpired;

    long expiresIn;

    public static DefaultRefreshTokenDetails of(OAuth2AuthorizedRefreshToken refreshToken) {
        return DefaultRefreshTokenDetails.builder()
                .tokenValue(refreshToken.getTokenId().getValue())
                .expiration(refreshToken.getExpiration())
                .isExpired(refreshToken.isExpired())
                .expiresIn(refreshToken.expiresIn()).build();
    }

    @Override
    public boolean getExpired() {
        return isExpired;
    }
}
