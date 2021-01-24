package cube8540.oauth.authentication.oauth.token.domain

interface OAuth2AccessTokenReadRepository {

    fun readAccessTokenWithClientByUsername(username: String): List<AccessTokenDetailsWithClient>
}