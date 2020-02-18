package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import lombok.Value;

@Value
public class DefaultOAuth2ScopeDetails implements OAuth2ScopeDetails {

    private String scopeId;

    private String description;

    public DefaultOAuth2ScopeDetails(OAuth2Scope scope) {
        this.scopeId = scope.getId().getValue();
        this.description = scope.getDescription();
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
