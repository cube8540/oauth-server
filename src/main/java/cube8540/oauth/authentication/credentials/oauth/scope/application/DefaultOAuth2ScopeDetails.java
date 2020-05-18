package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import lombok.Value;

@Value
public class DefaultOAuth2ScopeDetails implements AuthorityDetails {

    String code;

    String description;

    public static DefaultOAuth2ScopeDetails of(OAuth2Scope scope) {
        return new DefaultOAuth2ScopeDetails(scope.getCode().getValue(), scope.getDescription());
    }
}
