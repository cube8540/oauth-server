package cube8540.oauth.authentication.oauth.scope.application

interface OAuth2ScopeManagementService {

    fun countByScopeId(scopeId: String): Long

    fun registerNewScope(registerRequest: OAuth2ScopeRegisterRequest): OAuth2ScopeDetails

    fun modifyScope(scopeId: String, modifyRequest: OAuth2ScopeModifyRequest): OAuth2ScopeDetails

    fun removeScope(scopeId: String): OAuth2ScopeDetails

}