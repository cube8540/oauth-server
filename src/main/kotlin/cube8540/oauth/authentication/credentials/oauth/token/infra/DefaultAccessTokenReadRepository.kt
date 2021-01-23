package cube8540.oauth.authentication.credentials.oauth.token.infra

import cube8540.oauth.authentication.credentials.oauth.token.domain.AccessTokenDetailsWithClient
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenReadRepository
import cube8540.oauth.authentication.credentials.oauth.token.domain.PrincipalUsername
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Repository
import javax.persistence.EntityManager

@Repository
class DefaultAccessTokenReadRepository @Autowired constructor(private val entityManager: EntityManager): OAuth2AccessTokenReadRepository {

    companion object {
        protected const val ACCESS_TOKEN_WITH_CLIENT_BY_USERNAME_QUERY = """
                select new cube8540.oauth.authentication.credentials.oauth.token.infra.DefaultAccessTokenDetailsWithClient(token, client)
                from OAuth2AuthorizedAccessToken token, OAuth2Client client
                where token.username = :username and token.client.value = client.clientId.value
            """
    }

    override fun readAccessTokenWithClientByUsername(username: String): List<AccessTokenDetailsWithClient> =
        entityManager.createQuery(ACCESS_TOKEN_WITH_CLIENT_BY_USERNAME_QUERY, AccessTokenDetailsWithClient::class.java)
            .setParameter("username", PrincipalUsername(username))
            .resultList
}