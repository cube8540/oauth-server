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

import java.time.LocalDateTime;
import java.util.Set;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuth2AuthorizationCode extends AbstractAggregateRoot<OAuth2AuthorizationCode> {

    private AuthorizationCode code;

    private LocalDateTime expirationDateTime;

    private OAuth2ClientId clientId;

    private UserEmail email;

    private String state;

    private String redirectURI;

    @Singular("approvedScope")
    private Set<OAuth2ScopeId> approvedScopes;

    public static OAuth2AuthorizationCodeBuilder builder(AuthorizationCodeGenerator generator, LocalDateTime expirationDateTime) {
        return new OAuth2AuthorizationCodeBuilder()
                .code(generator.generate())
                .expirationDateTime(expirationDateTime);
    }
}
