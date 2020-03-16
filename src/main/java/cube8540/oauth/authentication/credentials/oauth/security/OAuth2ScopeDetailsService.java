package cube8540.oauth.authentication.credentials.oauth.security;

import java.util.Collection;

public interface OAuth2ScopeDetailsService {

    Collection<OAuth2ScopeDetails> loadScopeDetailsByScopeIds(Collection<String> scopeIds);

}