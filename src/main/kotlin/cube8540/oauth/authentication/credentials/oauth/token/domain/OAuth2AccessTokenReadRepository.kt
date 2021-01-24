package cube8540.oauth.authentication.credentials.oauth.token.domain

interface OAuth2AccessTokenReadRepository {

    fun readAccessTokenWithClientByUsername(username: String): List<AccessTokenDetailsWithClient>
}