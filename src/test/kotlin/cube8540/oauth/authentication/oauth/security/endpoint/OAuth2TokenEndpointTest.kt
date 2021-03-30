package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.TokenRequestKey
import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.security.*
import cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsToken
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import java.net.URI
import java.security.Principal

class OAuth2TokenEndpointTest {

    private val accessTokenGranter: OAuth2AccessTokenGranter = mockk()
    private val revoker: OAuth2TokenRevoker = mockk()

    private val endpoint = OAuth2TokenEndpoint(accessTokenGranter, revoker)

    @Nested
    inner class GrantTokenTest {

        @Test
        fun `grant token when principal class type is not client credentials`() {
            val principal: Principal = mockk(relaxed = true)
            val requestMap: MutableMap<String, String?> = HashMap()

            val thrown = catchThrowable { endpoint.grantNewAccessToken(principal, requestMap) }
            assertThat(thrown).isInstanceOf(InsufficientAuthenticationException::class.java)
        }

        @Test
        fun `grant token when principal details class type is not client details`() {
            val principal: ClientCredentialsToken = mockk {
                every { principal } returns mockk<Principal>(relaxed = true)
            }
            val requestMap: MutableMap<String, String?> = HashMap()

            val thrown = catchThrowable { endpoint.grantNewAccessToken(principal, requestMap) }
            assertThat(thrown).isInstanceOf(InsufficientAuthenticationException::class.java)
        }

        @Test
        fun `grant token when request grant type is null`() {
            val principal: ClientCredentialsToken = mockk {
                every { principal } returns mockk<OAuth2ClientDetails>(relaxed = true)
            }
            val requestMap: MutableMap<String, String?> = HashMap()

            requestMap[TokenRequestKey.GRANT_TYPE] = null

            val thrown = catchThrowable { endpoint.grantNewAccessToken(principal, requestMap) }
            assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
            assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        @Test
        fun `grant token when request grant type is implicit`() {
            val principal: ClientCredentialsToken = mockk {
                every { principal } returns mockk<OAuth2ClientDetails>(relaxed = true)
            }
            val requestMap: MutableMap<String, String?> = HashMap()

            requestMap[TokenRequestKey.GRANT_TYPE] = AuthorizationGrantType.IMPLICIT.value

            val thrown = catchThrowable { endpoint.grantNewAccessToken(principal, requestMap) }
            assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
            assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE)
        }

        @Test
        fun `grant new access token`() {
            val tokenRequestCaptor = slot<OAuth2TokenRequest>()
            val accessToken: OAuth2AccessTokenDetails = mockk(relaxed = true)
            val clientDetails: OAuth2ClientDetails = mockk {
                every { clientId } returns "clientId"
                every { scopes } returns setOf("client-scope-1", "client-scope-2", "client-scope-3")
            }
            val principal: ClientCredentialsToken = mockk {
                every { principal } returns clientDetails
            }
            val requestMap: MutableMap<String, String?> = HashMap()

            requestMap[TokenRequestKey.USERNAME] = "username"
            requestMap[TokenRequestKey.PASSWORD] = "password"
            requestMap[TokenRequestKey.CLIENT_ID] = "clientId"
            requestMap[TokenRequestKey.CODE] = "code"
            requestMap[TokenRequestKey.REDIRECT_URI] = "http://localhost/callback"
            requestMap[TokenRequestKey.GRANT_TYPE] = AuthorizationGrantType.AUTHORIZATION_CODE.value
            every { accessTokenGranter.grant(clientDetails, capture(tokenRequestCaptor)) } returns accessToken

            val result = endpoint.grantNewAccessToken(principal, requestMap)
            assertThat(tokenRequestCaptor.captured.username).isEqualTo("username")
            assertThat(tokenRequestCaptor.captured.password).isEqualTo("password")
            assertThat(tokenRequestCaptor.captured.code).isEqualTo("code")
            assertThat(tokenRequestCaptor.captured.redirectUri).isEqualTo(URI.create("http://localhost/callback"))
            assertThat(tokenRequestCaptor.captured.grantType).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE)
            assertThat(result.body).isEqualTo(accessToken)
            assertThat(result.headers.pragma).isEqualTo("no-cache")
        }
    }

    @Nested
    inner class RevokerTokenTest {

        @Test
        fun `revoke token when principal class type is not client credentials`() {
            val principal: Principal = mockk()

            val thrown = catchThrowable { endpoint.revokeAccessToken(principal, "tokenId") }
            assertThat(thrown).isInstanceOf(InsufficientAuthenticationException::class.java)
        }

        @Test
        fun `revoke token when request token is null`() {
            val principal: ClientCredentialsToken = mockk()

            val thrown = catchThrowable { endpoint.revokeAccessToken(principal, null) }
            assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
            assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        @Test
        fun `revoke successful`() {
            val revokedToken: OAuth2AccessTokenDetails = mockk()
            val principal: ClientCredentialsToken = mockk()

            every { revoker.revoke("tokenId") } returns revokedToken

            val result = endpoint.revokeAccessToken(principal, "tokenId")
            assertThat(result.body).isEqualTo(revokedToken)
        }
    }
}