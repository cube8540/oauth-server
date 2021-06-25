package cube8540.oauth.authentication.oauth.scope.application

interface OAuth2ScopeDetailsService {
    fun loadScopes(): Collection<OAuth2ScopeDetails>
}