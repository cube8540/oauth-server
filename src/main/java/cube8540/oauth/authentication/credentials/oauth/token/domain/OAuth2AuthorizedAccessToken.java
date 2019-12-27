package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.users.domain.UserEmail;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuth2AuthorizedAccessToken extends AbstractAggregateRoot<OAuth2AuthorizedAccessToken> {

    private OAuth2AuthenticationId authenticationId;

    private OAuth2TokenId tokenId;

    private UserEmail email;

    private OAuth2Client client;

    private LocalDateTime expiration;

    @Setter
    private OAuth2AuthorizedRefreshToken refreshToken;

    private Map<String, Object> additionalInformation;

    public OAuth2AuthorizedAccessToken(OAuth2AuthenticationIdGenerator authenticationIdGenerator,
                                       OAuth2TokenIdGenerator tokenIdGenerator,
                                       String email, OAuth2Client client, LocalDateTime expiration) {
        this.authenticationId = authenticationIdGenerator.extractAuthenticationValue();
        this.tokenId = tokenIdGenerator.extractTokenValue();
        this.email = new UserEmail(email);
        this.client = client;
        this.expiration = expiration;
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
