package cube8540.oauth.authentication.oauth.token.application

import com.nimbusds.oauth2.sdk.pkce.CodeChallenge
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest
import cube8540.oauth.authentication.oauth.token.domain.AuthorizationCodeGenerator
import cube8540.oauth.authentication.oauth.token.domain.AuthorizationCodeRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCode
import cube8540.oauth.authentication.oauth.token.domain.PrincipalUsername
import cube8540.oauth.authentication.security.AuthorityCode
import io.mockk.*
import java.net.URI
import java.util.Optional
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class CompositionAuthorizationCodeServiceTest {

    private val generator: AuthorizationCodeGenerator = mockk()
    private val repository: AuthorizationCodeRepository = mockk(relaxed = true) {
        every { save(any()) } returnsArgument 0
    }

    private val service = CompositionAuthorizationCodeService(repository)

    init {
        service.codeGenerator = generator
    }

    @Nested
    inner class ConsumeTest {

        @Test
        fun `authorization code not registered`() {
            every { repository.findById("authorizationCode") } returns Optional.empty()

            val result = service.consume("authorizationCode")
            assertThat(result).isNull()
            verify(exactly = 0) { repository.delete(any()) }
        }

        @Test
        fun `authorization code successful`() {
            val authorizationCode: OAuth2AuthorizationCode = mockk()

            every { repository.findById("authorizationCode") } returns Optional.of(authorizationCode)

            val result = service.consume("authorizationCode")
            assertThat(result).isEqualTo(authorizationCode)
            verify(exactly = 1) { repository.delete(authorizationCode) }
        }
    }

    @Nested
    inner class CodeGenerateTest {

        @Test
        fun `generate new code`() {
            val codeArgumentCaptor = slot<OAuth2AuthorizationCode>()
            val authorizationRequest: AuthorizationRequest = mockk {
                every { clientId } returns "clientId"
                every { requestScopes } returns setOf("scope-1", "scope-2", "scope-3")
                every { redirectUri } returns URI.create("http://localhost")
                every { username } returns "username"
                every { codeChallengeMethod } returns CodeChallengeMethod.S256
                every { codeChallenge } returns CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
            }

            every { generator.generate() } returns "authorizationCode"
            every { repository.save(capture(codeArgumentCaptor)) } returnsArgument 0

            service.generateNewAuthorizationCode(authorizationRequest)
            assertThat(codeArgumentCaptor.isCaptured).isTrue
            assertThat(codeArgumentCaptor.captured.code).isEqualTo("authorizationCode")
            assertThat(codeArgumentCaptor.captured.username).isEqualTo(PrincipalUsername("username"))
            assertThat(codeArgumentCaptor.captured.approvedScopes).isEqualTo(
                setOf(AuthorityCode("scope-1"), AuthorityCode("scope-2"), AuthorityCode("scope-3")))
            assertThat(codeArgumentCaptor.captured.redirectURI).isEqualTo(URI.create("http://localhost"))
            assertThat(codeArgumentCaptor.captured.codeChallengeMethod).isEqualTo(CodeChallengeMethod.S256)
            assertThat(codeArgumentCaptor.captured.codeChallenge).isEqualTo(CodeChallenge.compute(CodeChallengeMethod.S256, CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")))
        }
    }

    @AfterEach
    fun afterClear() {
        clearAllMocks()
    }
}