package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.OAuth2RefreshTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import lombok.Builder;
import lombok.Value;

import java.time.LocalDateTime;

@Value
@Builder
public class DefaultRefreshTokenDetails implements OAuth2RefreshTokenDetails {

    private String tokenValue;
    private LocalDateTime expiration;
    private boolean isExpired;
    private long expiresIn;

    public static DefaultRefreshTokenDetails of(OAuth2AuthorizedRefreshToken refreshToken) {
        return DefaultRefreshTokenDetails.builder()
                .tokenValue(refreshToken.getTokenId().getValue())
                .expiration(refreshToken.getExpiration())
                .isExpired(refreshToken.isExpired())
                .expiresIn(refreshToken.expiresIn()).build();
    }
}
