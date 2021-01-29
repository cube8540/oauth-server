package cube8540.oauth.authentication.users.application

import cube8540.oauth.authentication.oauth.security.AutoApprovalScopeHandler
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.users.domain.ApprovalAuthority
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.security.Principal

@Service
class UserAutoApprovalScopeHandler @Autowired constructor(private val approvalService: UserApprovalAuthorityService): AutoApprovalScopeHandler {

    override fun filterRequiredPermissionScopes(authentication: Principal, clientDetails: OAuth2ClientDetails, requestScopes: Set<String>): Set<String> {
        val approvals = approvalService.getApprovalAuthorities(authentication.name)
            .filter { it.clientId == clientDetails.clientId }
            .map { it.scopeId }

        return requestScopes.subtract(approvals)
    }

    override fun storeAutoApprovalScopes(authentication: Principal, clientDetails: OAuth2ClientDetails, approvalScopes: Set<String>) {
        val authorities = approvalScopes.map { ApprovalAuthority(clientDetails.clientId, it) }.toSet()

        approvalService.grantApprovalAuthorities(authentication.name, authorities)
    }
}