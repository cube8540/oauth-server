package cube8540.oauth.authentication.oauth.token.domain

import com.nimbusds.oauth2.sdk.pkce.CodeChallenge
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import cube8540.oauth.authentication.AuthenticationApplication
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidClientException
import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.error.RedirectMismatchException
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.toDefaultInstance
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import java.net.URI
import java.time.Clock
import java.time.LocalDateTime

class OAuth2AuthorizationCodeTest {

    private val codeCreationDateTime = LocalDateTime.of(2020, 2, 8, 23, 22)
    private val codeGenerator: AuthorizationCodeGenerator = mockk {
        every { generate() } returns "authorizationCode"
    }
    private val code: OAuth2AuthorizationCode

    init {
        OAuth2AuthorizationCode.clock = Clock.fixed(codeCreationDateTime.toDefaultInstance(),
            AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
        this.code = OAuth2AuthorizationCode(codeGenerator)
    }

    @Nested
    inner class CreationAuthorizationCode {

        @Test
        fun `initialization code`() {
            assertThat(code.code).isEqualTo("authorizationCode")
            assertThat(code.expirationDateTime).isEqualTo(codeCreationDateTime.plusMinutes(5))
        }
    }

    @Nested
    inner class SavedAuthorizationRequestTest {

        @Test
        fun `save authorization request`() {
            val request: AuthorizationRequest = mockk {
                every { clientId } returns "clientId"
                every { username } returns "username"
                every { redirectUri } returns URI.create("http://localhost")
                every { requestScopes } returns setOf("scope-1", "scope-2", "scope-3")
                every { codeChallengeMethod } returns CodeChallengeMethod.S256
                every { codeChallenge } returns CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
            }

            code.setAuthorizationRequest(request)
            assertThat(code.clientId).isEqualTo(OAuth2ClientId("clientId"))
            assertThat(code.username).isEqualTo(PrincipalUsername("username"))
            assertThat(code.redirectURI).isEqualTo(URI.create("http://localhost"))
            assertThat(code.approvedScopes).isEqualTo(setOf(AuthorityCode("scope-1"), AuthorityCode("scope-2"), AuthorityCode("scope-3")))
            assertThat(code.codeChallengeMethod).isEqualTo(CodeChallengeMethod.S256)
            assertThat(code.codeChallenge).isEqualTo(CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")))
        }

        @Test
        fun `when code challenge is not null and code challenge method is null`() {
            val request: AuthorizationRequest = mockk {
                every { clientId } returns "clientId"
                every { username } returns "username"
                every { redirectUri } returns URI.create("http://localhost")
                every { requestScopes } returns setOf("scope-1", "scope-2", "scope-3")
                every { codeChallengeMethod } returns null
                every { codeChallenge } returns CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
            }

            code.setAuthorizationRequest(request)
            assertThat(code.clientId).isEqualTo(OAuth2ClientId("clientId"))
            assertThat(code.username).isEqualTo(PrincipalUsername("username"))
            assertThat(code.redirectURI).isEqualTo(URI.create("http://localhost"))
            assertThat(code.approvedScopes).isEqualTo(setOf(AuthorityCode("scope-1"), AuthorityCode("scope-2"), AuthorityCode("scope-3")))
            assertThat(code.codeChallengeMethod).isEqualTo(CodeChallengeMethod.PLAIN)
            assertThat(code.codeChallenge).isEqualTo(CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")))
        }

        @Test
        fun `when code challenge is null and code challenge method is not null`() {
            val request: AuthorizationRequest = mockk {
                every { clientId } returns "clientId"
                every { username } returns "username"
                every { redirectUri } returns URI.create("http://localhost")
                every { requestScopes } returns setOf("scope-1", "scope-2", "scope-3")
                every { codeChallengeMethod } returns CodeChallengeMethod.PLAIN
                every { codeChallenge } returns null
            }

            val thrown = catchThrowable { code.setAuthorizationRequest(request) }
            assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
            assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT)
        }

        @Test
        fun `when code challenge is null and code challenge method is null`() {
            val request: AuthorizationRequest = mockk {
                every { clientId } returns "clientId"
                every { username } returns "username"
                every { redirectUri } returns URI.create("http://localhost")
                every { requestScopes } returns setOf("scope-1", "scope-2", "scope-3")
                every { codeChallengeMethod } returns null
                every { codeChallenge } returns null
            }

            code.setAuthorizationRequest(request)
            assertThat(code.clientId).isEqualTo(OAuth2ClientId("clientId"))
            assertThat(code.username).isEqualTo(PrincipalUsername("username"))
            assertThat(code.redirectURI).isEqualTo(URI.create("http://localhost"))
            assertThat(code.approvedScopes).isEqualTo(setOf(AuthorityCode("scope-1"), AuthorityCode("scope-2"), AuthorityCode("scope-3")))
            assertThat(code.codeChallengeMethod).isNull()
            assertThat(code.codeChallenge).isNull()
        }
    }

    @Nested
    inner class ValidationTest {

        @Test
        fun `code is expired`() {
            val storedAuthorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { username } returns "username"
                every { redirectUri } returns URI.create("http://localhost")
                every { requestScopes } returns setOf("scope-1", "scope-2", "scope-3")
                every { codeChallengeMethod } returns CodeChallengeMethod.S256
                every { codeChallenge } returns CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
            }
            val tokenRequest: OAuth2TokenRequest = mockk(relaxed = true)

            OAuth2AuthorizationCode.clock = Clock.fixed(codeCreationDateTime.plusMinutes(5).plusNanos(1).toDefaultInstance(),
                AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            code.setAuthorizationRequest(storedAuthorizationRequest)

            val thrown = catchThrowable { code.validateWithAuthorizationRequest(tokenRequest) }
            assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
            assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT)
        }

        @Test
        fun `code stored redirect uri is null and token requested uri is not null`() {
            val storedAuthorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeChallengeMethod } returns CodeChallengeMethod.S256
                every { codeChallenge } returns CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
            }
            val tokenRequest: OAuth2TokenRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns null
                every { codeVerifier } returns CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")
            }

            OAuth2AuthorizationCode.clock = Clock.fixed(codeCreationDateTime.plusMinutes(5).minusNanos(1).toDefaultInstance(),
                AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            code.setAuthorizationRequest(storedAuthorizationRequest)

            val thrown = catchThrowable { code.validateWithAuthorizationRequest(tokenRequest) }
            assertThat(thrown).isInstanceOf(RedirectMismatchException::class.java)
        }

        @Test
        fun `request redirect uri is different stored redirect uri`() {
            val storedAuthorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeChallengeMethod } returns CodeChallengeMethod.S256
                every { codeChallenge } returns CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
            }
            val tokenRequest: OAuth2TokenRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost:8080")
                every { codeVerifier } returns CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")
            }

            OAuth2AuthorizationCode.clock = Clock.fixed(codeCreationDateTime.plusMinutes(5).minusNanos(1).toDefaultInstance(),
                AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            code.setAuthorizationRequest(storedAuthorizationRequest)

            val thrown = catchThrowable { code.validateWithAuthorizationRequest(tokenRequest) }
            assertThat(thrown).isInstanceOf(RedirectMismatchException::class.java)
        }

        @Test
        fun `request client id is different stored client id`() {
            val storedAuthorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeChallengeMethod } returns CodeChallengeMethod.S256
                every { codeChallenge } returns CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
            }
            val tokenRequest: OAuth2TokenRequest = mockk(relaxed = true) {
                every { clientId } returns "differentId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeVerifier } returns CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")
            }

            OAuth2AuthorizationCode.clock = Clock.fixed(codeCreationDateTime.plusMinutes(5).minusNanos(1).toDefaultInstance(),
                AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            code.setAuthorizationRequest(storedAuthorizationRequest)

            val thrown = catchThrowable { code.validateWithAuthorizationRequest(tokenRequest) }
            assertThat(thrown).isInstanceOf(InvalidClientException::class.java)
            assertThat((thrown as InvalidClientException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT)
        }

        @Test
        fun `stored code challenge is not null and request code verifier is null`() {
            val storedAuthorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeChallengeMethod } returns CodeChallengeMethod.S256
                every { codeChallenge } returns CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
            }
            val tokenRequest: OAuth2TokenRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeVerifier } returns null
            }

            OAuth2AuthorizationCode.clock = Clock.fixed(codeCreationDateTime.plusMinutes(5).minusNanos(1).toDefaultInstance(),
                AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            code.setAuthorizationRequest(storedAuthorizationRequest)

            val thrown = catchThrowable { code.validateWithAuthorizationRequest(tokenRequest) }
            assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
            assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT)
        }

        @Test
        fun `stored code challenge is null and request code verifier is not null`() {
            val storedAuthorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeChallengeMethod } returns null
                every { codeChallenge } returns null
            }
            val tokenRequest: OAuth2TokenRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeVerifier } returns CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")
            }

            OAuth2AuthorizationCode.clock = Clock.fixed(codeCreationDateTime.plusMinutes(5).minusNanos(1).toDefaultInstance(),
            AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            code.setAuthorizationRequest(storedAuthorizationRequest)

            val thrown = catchThrowable { code.validateWithAuthorizationRequest(tokenRequest) }
            assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
            assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT)
        }

        @Test
        fun `request code verifier is not matches stored code challenge`() {
            val storedAuthorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeChallengeMethod } returns CodeChallengeMethod.S256
                every { codeChallenge } returns CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
            }
            val tokenRequest: OAuth2TokenRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeVerifier } returns CodeVerifier("AnBhW7vVk8j4tdsc6jqcZ6YIwHbWhFzpIctxyTCv8jC")
            }

            OAuth2AuthorizationCode.clock = Clock.fixed(codeCreationDateTime.plusMinutes(5).minusNanos(1).toDefaultInstance(),
                AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            code.setAuthorizationRequest(storedAuthorizationRequest)

            val thrown = catchThrowable { code.validateWithAuthorizationRequest(tokenRequest) }
            assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
            assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT)
        }

        @Test
        fun `stored code challenge is null and request code verifier is null`() {
            val storedAuthorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeChallengeMethod } returns null
                every { codeChallenge } returns null
            }
            val tokenRequest: OAuth2TokenRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeVerifier } returns null
            }

            OAuth2AuthorizationCode.clock = Clock.fixed(codeCreationDateTime.plusMinutes(5).minusNanos(1).toDefaultInstance(),
                AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            code.setAuthorizationRequest(storedAuthorizationRequest)

            assertDoesNotThrow { code.validateWithAuthorizationRequest(tokenRequest) }
        }

        @Test
        fun `token request information matches stored request`() {
            val storedAuthorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeChallengeMethod } returns CodeChallengeMethod.S256
                every { codeChallenge } returns CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
            }
            val tokenRequest: OAuth2TokenRequest = mockk(relaxed = true) {
                every { clientId } returns "clientId"
                every { redirectUri } returns URI.create("http://localhost")
                every { codeVerifier } returns CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")
            }

            OAuth2AuthorizationCode.clock = Clock.fixed(codeCreationDateTime.plusMinutes(5).minusNanos(1).toDefaultInstance(),
                AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            code.setAuthorizationRequest(storedAuthorizationRequest)

            assertDoesNotThrow { code.validateWithAuthorizationRequest(tokenRequest) }
        }
    }

}