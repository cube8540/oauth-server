package cube8540.oauth.authentication.oauth.token.infra

import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client
import cube8540.oauth.authentication.oauth.token.domain.AccessTokenClient
import cube8540.oauth.authentication.oauth.token.domain.AccessTokenDetailsWithClient
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import java.time.LocalDateTime

data class DefaultClient(override val clientId: String?, override val clientName: String?) : AccessTokenClient

data class DefaultAccessTokenDetailsWithClient(
    override val tokenValue: String?,

    override val client: AccessTokenClient?,

    override val username: String?,

    override val issuedAt: LocalDateTime?,

    override val expiresIn: Long?,

    override val additionalInformation: Map<String, String?>?
): AccessTokenDetailsWithClient {

    constructor(accessToken: OAuth2AuthorizedAccessToken, client: OAuth2Client): this(
        tokenValue = accessToken.tokenId.value,
        client = DefaultClient(client.clientId.value, client.clientName),
        username = accessToken.username?.value,
        issuedAt = accessToken.issuedAt,
        expiresIn = accessToken.expiresIn(),
        additionalInformation = accessToken.additionalInformation?.toMap()
    )
}