package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Singular;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
public class OAuth2AuthorizedAccessToken extends AbstractAggregateRoot<OAuth2AuthorizedAccessToken> {

    private OAuth2TokenId tokenId;

    private UserEmail email;

    private OAuth2ClientId client;

    @Singular("scope")
    private Set<OAuth2ScopeId> scope;

    private LocalDateTime expiration;

    private AuthorizationGrantType tokenGrantType;

    private OAuth2AuthorizedRefreshToken refreshToken;

    private Map<String, Object> additionalInformation;

    public static OAuth2AuthorizedAccessTokenBuilder builder(OAuth2TokenIdGenerator tokenIdGenerator) {
        return new OAuth2AuthorizedAccessTokenBuilder()
                .tokenId(tokenIdGenerator.generateTokenValue());
    }

    public boolean isExpired() {
        return expiration.isBefore(LocalDateTime.now());
    }

    public long expiresIn() {
        if (isExpired()) {
            return 0;
        }
        return Duration.between(LocalDateTime.now(), expiration).toSeconds();
    }

    public void putAdditionalInformation(String key, String value) {
        if (this.additionalInformation == null) {
            this.additionalInformation = new HashMap<>();
        }
        this.additionalInformation.put(key, value);
    }
}
