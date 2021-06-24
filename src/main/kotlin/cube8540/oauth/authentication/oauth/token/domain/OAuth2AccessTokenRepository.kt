package cube8540.oauth.authentication.oauth.token.domain

import java.util.Optional
import org.springframework.data.jpa.repository.EntityGraph
import org.springframework.data.jpa.repository.JpaRepository

interface OAuth2AccessTokenRepository: JpaRepository<OAuth2AuthorizedAccessToken, OAuth2TokenId> {

    @EntityGraph(attributePaths = ["scopes", "refreshToken", "additionalInformation"])
    fun findByComposeUniqueKey(composeUniqueKey: OAuth2ComposeUniqueKey): Optional<OAuth2AuthorizedAccessToken>
}