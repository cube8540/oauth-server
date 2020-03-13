package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;

import java.util.Map;
import java.util.Set;

public interface ScopeApprovalResolver {

    Set<String> resolveApprovalScopes(AuthorizationRequest originalRequest, Map<String, String> approvalParameters);

}
