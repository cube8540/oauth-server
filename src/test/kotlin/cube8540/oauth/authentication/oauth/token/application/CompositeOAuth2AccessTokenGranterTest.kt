package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

class CompositeOAuth2AccessTokenGranterTest {

    @Test
    fun `not supported grant type`() {
        val accessTokenGranter = CompositeOAuth2AccessTokenGranter()

        val clientDetails: OAuth2ClientDetails = mockk()
        val request: OAuth2TokenRequest = mockk {
            every { grantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
        }

        val thrown = catchThrowable { accessTokenGranter.grant(clientDetails, request) }
        assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
        assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE)
    }

    @Test
    fun `generate access token`() {
        val accessTokenGranter = CompositeOAuth2AccessTokenGranter()
        val authorizationCodeGranter: AuthorizationCodeTokenGranter = mockk()
        val clientCredentialsGranter: ClientCredentialsTokenGranter = mockk()
        val passwordTokenGranter: ResourceOwnerPasswordTokenGranter = mockk()
        val refreshTokenGranter: RefreshTokenGranter = mockk()

        val accessToken: OAuth2AccessTokenDetails = mockk()
        val clientDetails: OAuth2ClientDetails = mockk()
        val request: OAuth2TokenRequest = mockk {
            every { grantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
        }

        every { authorizationCodeGranter.grant(clientDetails, request) } returns accessToken
        accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.AUTHORIZATION_CODE, authorizationCodeGranter)
        accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.CLIENT_CREDENTIALS, clientCredentialsGranter)
        accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.PASSWORD, passwordTokenGranter)
        accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.REFRESH_TOKEN, refreshTokenGranter)

        val result = accessTokenGranter.grant(clientDetails, request)
        assertThat(result).isEqualTo(accessToken)
    }

}