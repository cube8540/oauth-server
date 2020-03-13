package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.error.UserDeniedAuthorizationException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class DefaultScopeApprovalResolver implements ScopeApprovalResolver {
    @Override
    public Set<String> resolveApprovalScopes(AuthorizationRequest originalRequest, Map<String, String> approvalParameters) {
        Set<String> storedScopes = originalRequest.getRequestScopes();
        Set<String> approvalScopes = new HashSet<>();
        for (String storedScope : storedScopes) {
            String approval = approvalParameters.get(storedScope);
            if ("true".equalsIgnoreCase(approval)) {
                approvalScopes.add(storedScope);
            }
        }
        if (approvalScopes.isEmpty()) {
            throw new UserDeniedAuthorizationException("User denied access");
        }
        return Collections.unmodifiableSet(approvalScopes);
    }
}
