package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import org.springframework.security.core.Authentication;

import java.util.Collection;

public interface OAuth2AccessibleScopeDetailsService {

    Collection<AuthorityDetails> readAccessibleScopes(Authentication authentication);
}
