package cube8540.oauth.authentication.credentials.oauth.token.domain

import org.springframework.data.jpa.repository.JpaRepository

interface OAuth2RefreshTokenRepository: JpaRepository<OAuth2AuthorizedRefreshToken, OAuth2TokenId> {
}