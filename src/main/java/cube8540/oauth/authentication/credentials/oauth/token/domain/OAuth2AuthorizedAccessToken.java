package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.converter.AuthorizationGrantTypeConverter;
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
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.springframework.data.domain.AbstractAggregateRoot;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import javax.persistence.AttributeOverride;
import javax.persistence.CascadeType;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.ElementCollection;
import javax.persistence.Embedded;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.MapKeyColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
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
@Entity
@Table(name = "oauth2_access_token", uniqueConstraints = {
        @UniqueConstraint(name = "client_authentication_username", columnNames = {"client_id", "email"})
})
@DynamicInsert
@DynamicUpdate
public class OAuth2AuthorizedAccessToken extends AbstractAggregateRoot<OAuth2AuthorizedAccessToken> {

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "token_id", length = 32))
    private OAuth2TokenId tokenId;

    @Embedded
    @AttributeOverride(name = "value", column = @Column(name = "email", length = 128))
    private UserEmail email;

    @Embedded
    @AttributeOverride(name = "value", column = @Column(name = "client_id", length = 32, nullable = false))
    private OAuth2ClientId client;

    @Singular("scope")
    @ElementCollection
    @CollectionTable(name = "oauth2_token_scope", joinColumns = @JoinColumn(name = "token_id", nullable = false))
    @AttributeOverride(name = "value", column = @Column(name = "scope_id", length = 32, nullable = false))
    private Set<OAuth2ScopeId> scope;

    @Column(name = "expiration", nullable = false)
    private LocalDateTime expiration;

    @Column(name = "grant_type", nullable = false, length = 32)
    @Convert(converter = AuthorizationGrantTypeConverter.class)
    private AuthorizationGrantType tokenGrantType;

    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "accessToken")
    @JoinColumn(name = "access_token_id")
    private OAuth2AuthorizedRefreshToken refreshToken;

    @ElementCollection
    @JoinTable(name = "oauth2_access_token_additional_information", joinColumns = @JoinColumn(name = "token_id"))
    @MapKeyColumn(name = "info_key")
    @Column(name = "info_value", length = 128)
    private Map<String, String> additionalInformation;

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

    public void generateRefreshToken(OAuth2TokenIdGenerator refreshTokenIdGenerator, LocalDateTime expirationDateTime) {
        this.refreshToken = new OAuth2AuthorizedRefreshToken(refreshTokenIdGenerator, expirationDateTime, this);
    }
}
