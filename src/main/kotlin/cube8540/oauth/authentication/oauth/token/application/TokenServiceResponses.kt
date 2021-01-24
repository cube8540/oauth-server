package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2RefreshTokenDetails
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedRefreshToken
import java.time.LocalDateTime

data class DefaultAccessTokenDetails(
    override val tokenValue: String,

    override val clientId: String?,

    override val tokenType: String?,

    override val username: String?,

    override val scopes: Set<String>?,

    override val expiration: LocalDateTime,

    override val expired: Boolean,

    override val expiresIn: Long,

    override val refreshToken: OAuth2RefreshTokenDetails?,

    override val additionalInformation: Map<String, String?>?
): OAuth2AccessTokenDetails {
    companion object {
        private const val TOKEN_TYPE = "Bearer"

        @JvmStatic
        fun of(accessToken: OAuth2AuthorizedAccessToken): DefaultAccessTokenDetails =
            DefaultAccessTokenDetails(
                tokenValue = accessToken.tokenId.value,
                clientId = accessToken.client.value,
                tokenType = TOKEN_TYPE,
                username = accessToken.username?.value,
                scopes = accessToken.scopes.map(AuthorityCode::value).toSet(),
                expiration = accessToken.expiration,
                expired = accessToken.isExpired(),
                expiresIn = accessToken.expiresIn(),
                refreshToken = accessToken.refreshToken?.let(DefaultRefreshTokenDetails::of),
                additionalInformation = accessToken.additionalInformation
            )
    }
}

data class DefaultRefreshTokenDetails(
    override val tokenValue: String,

    override val expiration: LocalDateTime,

    override val expired: Boolean,

    override val expiresIn: Long
): OAuth2RefreshTokenDetails {
    companion object {
        @JvmStatic
        fun of(refreshToken: OAuth2AuthorizedRefreshToken): DefaultRefreshTokenDetails =
            DefaultRefreshTokenDetails(
                tokenValue = refreshToken.tokenId.value,
                expiration = refreshToken.expiration,
                expired = refreshToken.isExpired(),
                expiresIn = refreshToken.expiresIn()
            )
    }
}