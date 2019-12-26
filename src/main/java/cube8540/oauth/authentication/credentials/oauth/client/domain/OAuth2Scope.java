package cube8540.oauth.authentication.credentials.oauth.client.domain;

import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@EqualsAndHashCode
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuth2Scope {

    private OAuth2ScopeId id;

    private String description;

    public OAuth2Scope(String scopeId, String description) {
        this.id = new OAuth2ScopeId(scopeId);
        this.description = description;
    }
}
