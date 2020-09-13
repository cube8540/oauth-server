package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.AuthorityDetailsService;

import java.util.Collection;

public interface OAuth2ScopeManagementService extends AuthorityDetailsService {

    Long countByScopeId(String scopeId);

    Collection<AuthorityDetails> loadAllScopes();

    Collection<AuthorityDetails> loadPublicScopes();

    AuthorityDetails registerNewScope(OAuth2ScopeRegisterRequest registerRequest);

    AuthorityDetails modifyScope(String scopeId, OAuth2ScopeModifyRequest modifyRequest);

    AuthorityDetails removeScope(String scopeId);

}
