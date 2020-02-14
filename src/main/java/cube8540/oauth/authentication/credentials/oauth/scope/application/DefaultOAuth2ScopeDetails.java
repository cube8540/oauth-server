package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import lombok.Value;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Value
public class DefaultOAuth2ScopeDetails implements OAuth2ScopeDetails {

    private String scopeId;

    private String description;

    private Set<AuthorityCode> accessibleAuthority;

    public DefaultOAuth2ScopeDetails(OAuth2Scope scope) {
        this.scopeId = scope.getId().getValue();
        this.description = scope.getDescription();
        this.accessibleAuthority = Optional.ofNullable(scope.getAccessibleAuthority())
                .map(Set::stream)
                .map(stream -> stream.collect(Collectors.toUnmodifiableSet()))
                .orElse(Collections.emptySet());
    }

    @Override
    public String scopeId() {
        return scopeId;
    }

    @Override
    public String description() {
        return description;
    }
}
