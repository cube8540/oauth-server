package cube8540.oauth.authentication.oauth.error

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

class AbstractOAuth2AuthenticationTest {

    @Test
    fun `to string when error message is null`() {
        val error = OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST)
        val exception = AbstractOAuth2AuthenticationException(400, error)

        val result = exception.toString()
        assertThat(result).isEqualTo("error=\"invalid_request\"")
    }

    @Test
    fun `to string when include all property`() {
        val error = OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "invalid request", null)
        val exception = AbstractOAuth2AuthenticationException(400, error)

        val result = exception.toString()
        assertThat(result).isEqualTo("error=\"invalid_request\", error_description=\"invalid request\"")
    }

}