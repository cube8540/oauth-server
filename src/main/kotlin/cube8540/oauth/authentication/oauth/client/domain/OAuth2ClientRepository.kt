package cube8540.oauth.authentication.oauth.client.domain

import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.EntityGraph
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*

interface OAuth2ClientRepository: JpaRepository<OAuth2Client, OAuth2ClientId> {

    fun countByClientId(clientId: OAuth2ClientId): Long

    @EntityGraph(attributePaths = ["redirectUris", "grantTypes", "scopes"])
    fun findByClientId(clientId: OAuth2ClientId): Optional<OAuth2Client>

    fun findByOwner(owner: ClientOwner, pageable: Pageable): Page<OAuth2Client>

}