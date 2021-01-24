package cube8540.oauth.authentication.credentials.oauth.scope.application

import cube8540.oauth.authentication.credentials.AuthorityDetails
import cube8540.oauth.authentication.credentials.AuthorityDetailsService

interface OAuth2ScopeManagementService: AuthorityDetailsService {

    fun countByScopeId(scopeId: String): Long

    fun loadScopes(): Collection<AuthorityDetails>

    fun registerNewScope(registerRequest: OAuth2ScopeRegisterRequest): AuthorityDetails

    fun modifyScope(scopeId: String, modifyRequest: OAuth2ScopeModifyRequest): AuthorityDetails

    fun removeScope(scopeId: String): AuthorityDetails

}