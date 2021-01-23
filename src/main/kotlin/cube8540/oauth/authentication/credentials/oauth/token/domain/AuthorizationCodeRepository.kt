package cube8540.oauth.authentication.credentials.oauth.token.domain

import org.springframework.data.jpa.repository.EntityGraph
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*

interface AuthorizationCodeRepository: JpaRepository<OAuth2AuthorizationCode, String> {

    @EntityGraph(attributePaths = ["approvedScopes"], type = EntityGraph.EntityGraphType.LOAD)
    override fun findById(id: String): Optional<OAuth2AuthorizationCode>
}