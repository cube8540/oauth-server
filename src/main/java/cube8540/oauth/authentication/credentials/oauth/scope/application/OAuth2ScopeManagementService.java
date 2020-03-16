package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ScopeDetailsService;

public interface OAuth2ScopeManagementService extends OAuth2ScopeDetailsService {

    Long countByScopeId(String scopeId);

    OAuth2ScopeDetails registerNewScope(OAuth2ScopeRegisterRequest registerRequest);

    OAuth2ScopeDetails modifyScope(String scopeId, OAuth2ScopeModifyRequest modifyRequest);

    OAuth2ScopeDetails removeScope(String scopeId);

}
