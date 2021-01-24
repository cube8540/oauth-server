package cube8540.oauth.authentication.oauth.scope.application

import cube8540.oauth.authentication.security.AuthorityDetails
import cube8540.oauth.authentication.security.AuthorityDetailsService

interface OAuth2ScopeManagementService: AuthorityDetailsService {

    fun countByScopeId(scopeId: String): Long

    fun loadScopes(): Collection<AuthorityDetails>

    fun registerNewScope(registerRequest: OAuth2ScopeRegisterRequest): AuthorityDetails

    fun modifyScope(scopeId: String, modifyRequest: OAuth2ScopeModifyRequest): AuthorityDetails

    fun removeScope(scopeId: String): AuthorityDetails

}