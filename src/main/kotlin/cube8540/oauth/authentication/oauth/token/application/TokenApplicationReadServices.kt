package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.token.domain.AccessTokenDetailsWithClient

interface AccessTokenReadService {
    fun getAuthorizeAccessTokens(username: String): List<AccessTokenDetailsWithClient>
}