package cube8540.oauth.authentication.credentials.oauth.scope.application

import cube8540.oauth.authentication.credentials.AuthorityDetails
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope

data class DefaultOAuth2ScopeDetails(
    override val code: String,

    override val description: String
): AuthorityDetails {
    companion object {
        @JvmStatic
        fun of(scope: OAuth2Scope): DefaultOAuth2ScopeDetails = DefaultOAuth2ScopeDetails(scope.code.value, scope.description)
    }
}