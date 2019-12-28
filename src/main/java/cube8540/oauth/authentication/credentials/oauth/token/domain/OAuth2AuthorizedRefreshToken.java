package cube8540.oauth.authentication.credentials.oauth.token.domain;

import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

import java.time.LocalDateTime;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuth2AuthorizedRefreshToken extends AbstractAggregateRoot<OAuth2AuthorizedRefreshToken> {

    private OAuth2TokenId tokenId;

    private LocalDateTime expiration;

    public OAuth2AuthorizedRefreshToken(OAuth2TokenIdGenerator tokenIdGenerator, LocalDateTime expiration) {
        this.tokenId = tokenIdGenerator.extractTokenValue();
        this.expiration = expiration;
    }

    public boolean isExpired() {
        return this.expiration.isBefore(LocalDateTime.now());
    }
}
