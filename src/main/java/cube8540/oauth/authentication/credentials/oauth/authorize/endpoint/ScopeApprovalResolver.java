package cube8540.oauth.authentication.credentials.oauth.authorize.endpoint;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;

import java.util.Map;
import java.util.Set;

public interface ScopeApprovalResolver {

    Set<String> resolveApprovalScopes(AuthorizationRequest originalRequest, Map<String, String> approvalParameters);

}
