package cube8540.oauth.authentication.oauth.security

import java.security.Principal

interface AutoApprovalScopeHandler {

    fun filterRequiredPermissionScopes(authentication: Principal, clientDetails: OAuth2ClientDetails, requestScopes: Set<String>): Set<String>

    fun storeAutoApprovalScopes(authentication: Principal, clientDetails: OAuth2ClientDetails, approvalScopes: Set<String>)

}