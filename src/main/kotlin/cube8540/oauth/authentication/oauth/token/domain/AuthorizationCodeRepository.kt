package cube8540.oauth.authentication.oauth.token.domain

import java.util.Optional
import org.springframework.data.jpa.repository.EntityGraph
import org.springframework.data.jpa.repository.JpaRepository

interface AuthorizationCodeRepository: JpaRepository<OAuth2AuthorizationCode, String> {

    @EntityGraph(attributePaths = ["approvedScopes"], type = EntityGraph.EntityGraphType.LOAD)
    override fun findById(id: String): Optional<OAuth2AuthorizationCode>
}