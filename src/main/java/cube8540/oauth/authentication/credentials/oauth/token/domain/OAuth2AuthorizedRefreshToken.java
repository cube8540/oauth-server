package cube8540.oauth.authentication.credentials.oauth.token.domain;

import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

import javax.persistence.AttributeOverride;
import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import java.time.LocalDateTime;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "oauth2_refresh_token")
public class OAuth2AuthorizedRefreshToken extends AbstractAggregateRoot<OAuth2AuthorizedRefreshToken> {

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "token_id", length = 32))
    private OAuth2TokenId tokenId;

    @Column(name = "expiration", nullable = false)
    private LocalDateTime expiration;

    @OneToOne(fetch = FetchType.EAGER)
    private OAuth2AuthorizedAccessToken accessToken;

    public OAuth2AuthorizedRefreshToken(OAuth2TokenIdGenerator tokenIdGenerator, LocalDateTime expiration, OAuth2AuthorizedAccessToken accessToken) {
        this.tokenId = tokenIdGenerator.generateTokenValue();
        this.expiration = expiration;
        this.accessToken = accessToken;
    }

    public boolean isExpired() {
        return this.expiration.isBefore(LocalDateTime.now());
    }
}
