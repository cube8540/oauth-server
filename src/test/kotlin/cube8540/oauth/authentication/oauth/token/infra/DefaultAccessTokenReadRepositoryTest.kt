package cube8540.oauth.authentication.oauth.token.infra

import cube8540.oauth.authentication.oauth.token.domain.AccessTokenDetailsWithClient
import cube8540.oauth.authentication.oauth.token.domain.PrincipalUsername
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import javax.persistence.EntityManager
import javax.persistence.TypedQuery

class DefaultAccessTokenReadRepositoryTest {

    private val entityManager: EntityManager = mockk()
    private val repository = DefaultAccessTokenReadRepository(entityManager)

    @Test
    fun `get access token details with client`() {
        val queryResult: List<AccessTokenDetailsWithClient> = mockk()
        val typedQuery: TypedQuery<AccessTokenDetailsWithClient> = mockk()

        every { entityManager.createQuery(DefaultAccessTokenReadRepository.ACCESS_TOKEN_WITH_CLIENT_BY_USERNAME_QUERY, AccessTokenDetailsWithClient::class.java) } returns typedQuery
        every { typedQuery.setParameter("username", PrincipalUsername("username")) } returns typedQuery
        every { typedQuery.resultList } returns queryResult

        val result = repository.readAccessTokenWithClientByUsername("username")
        assertThat(result).isEqualTo(queryResult)
    }
}