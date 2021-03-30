package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import io.mockk.verifyOrder
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.mockito.Mockito
import org.mockito.Mockito.CALLS_REAL_METHODS
import org.springframework.security.oauth2.core.AuthorizationGrantType
import java.util.*

@TestInstance(TestInstance.Lifecycle.PER_METHOD)
class AbstractOAuth2TokenGranterTest {

    private val tokenEnhancer: OAuth2TokenEnhancer = mockk(relaxed = true)
    private val composeUniqueKeyGenerator: OAuth2ComposeUniqueKeyGenerator = mockk(relaxed = true)
    private val tokenIdGenerator: OAuth2TokenIdGenerator = mockk(relaxed = true) {
        every { generateTokenValue() } returns OAuth2TokenId("tokenId")
    }
    private val tokenRepository: OAuth2AccessTokenRepository = mockk(relaxed = true) {
        every { save(any()) } returnsArgument 0
    }

    private val granter: AbstractOAuth2TokenGranter = Mockito.mock(AbstractOAuth2TokenGranter::class.java, CALLS_REAL_METHODS)

    init {
        granter.tokenIdGenerator = tokenIdGenerator
        granter.tokenRepository = tokenRepository
        granter.tokenEnhancer = tokenEnhancer
        granter.composeUniqueKeyGenerator = composeUniqueKeyGenerator
    }

    @Test
    fun `generate compose unique key to created access token`() {
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequest: OAuth2TokenRequest = mockk()
        val createdAccessToken: OAuth2AuthorizedAccessToken = mockk(relaxed = true)

        Mockito.`when`(granter.createAccessToken(clientDetails, tokenRequest)).thenReturn(createdAccessToken)

        granter.grant(clientDetails, tokenRequest)
        verifyOrder {
            createdAccessToken.generateComposeUniqueKey(composeUniqueKeyGenerator)
            tokenRepository.save(createdAccessToken)
        }
    }

    @Test
    fun `generate when already authenticated by same client id and grant type`() {
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequest: OAuth2TokenRequest = mockk()
        val existsAccessToken: OAuth2AuthorizedAccessToken = mockk(relaxed = true) {
            every { tokenId } returns OAuth2TokenId("existsTokenId")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
            every { isExpired() } returns false
        }
        val createdAccessToken: OAuth2AuthorizedAccessToken = mockk(relaxed = true) {
            every { tokenId } returns OAuth2TokenId("createdTokenId")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
            every { composeUniqueKey } returns OAuth2ComposeUniqueKey("composeUniqueKey")
        }

        every { tokenRepository.findByComposeUniqueKey(OAuth2ComposeUniqueKey("composeUniqueKey")) } returns Optional.of(existsAccessToken)
        Mockito.`when`(granter.createAccessToken(clientDetails, tokenRequest)).thenReturn(createdAccessToken)

        val result = granter.grant(clientDetails, tokenRequest)
        verify(exactly = 0) { tokenEnhancer.enhance(any()) }
        verify(exactly = 0) { tokenRepository.save(any()) }
        verify(exactly = 0) { tokenRepository.delete(any()) }
        verifyOrder {
            createdAccessToken.generateComposeUniqueKey(composeUniqueKeyGenerator)
            tokenRepository.findByComposeUniqueKey(OAuth2ComposeUniqueKey("composeUniqueKey"))
        }
        assertThat(result.tokenValue).isEqualTo("existsTokenId")
    }

    @Test
    fun `generate when already authenticated by same client and different grant type`() {
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequest: OAuth2TokenRequest = mockk()
        val existsAccessToken: OAuth2AuthorizedAccessToken = mockk(relaxed = true) {
            every { tokenId } returns OAuth2TokenId("existsTokenId")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
            every { isExpired() } returns false
        }
        val createdAccessToken: OAuth2AuthorizedAccessToken = mockk(relaxed = true) {
            every { tokenId } returns OAuth2TokenId("createdTokenId")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.PASSWORD
            every { composeUniqueKey } returns OAuth2ComposeUniqueKey("composeUniqueKey")
        }

        every { tokenRepository.findByComposeUniqueKey(OAuth2ComposeUniqueKey("composeUniqueKey")) } returns Optional.of(existsAccessToken)
        Mockito.`when`(granter.createAccessToken(clientDetails, tokenRequest)).thenReturn(createdAccessToken)

        val result = granter.grant(clientDetails, tokenRequest)
        verifyOrder {
            createdAccessToken.generateComposeUniqueKey(composeUniqueKeyGenerator)
            tokenRepository.findByComposeUniqueKey(OAuth2ComposeUniqueKey("composeUniqueKey"))
            tokenRepository.delete(existsAccessToken)
            tokenEnhancer.enhance(createdAccessToken)
            tokenRepository.save(createdAccessToken)
        }
        assertThat(result.tokenValue).isEqualTo("createdTokenId")
    }

    @Test
    fun `generate when exists access token is expired`() {
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequest: OAuth2TokenRequest = mockk()
        val existsAccessToken: OAuth2AuthorizedAccessToken = mockk(relaxed = true) {
            every { tokenId } returns OAuth2TokenId("existsTokenId")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
            every { isExpired() } returns true
        }
        val createdAccessToken: OAuth2AuthorizedAccessToken = mockk(relaxed = true) {
            every { tokenId } returns OAuth2TokenId("createdTokenId")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
            every { composeUniqueKey } returns OAuth2ComposeUniqueKey("composeUniqueKey")
        }

        every { tokenRepository.findByComposeUniqueKey(OAuth2ComposeUniqueKey("composeUniqueKey")) } returns Optional.of(existsAccessToken)
        Mockito.`when`(granter.createAccessToken(clientDetails, tokenRequest)).thenReturn(createdAccessToken)

        val result = granter.grant(clientDetails, tokenRequest)
        verifyOrder {
            createdAccessToken.generateComposeUniqueKey(composeUniqueKeyGenerator)
            tokenRepository.findByComposeUniqueKey(OAuth2ComposeUniqueKey("composeUniqueKey"))
            tokenRepository.delete(existsAccessToken)
            tokenEnhancer.enhance(createdAccessToken)
            tokenRepository.save(createdAccessToken)
        }
        assertThat(result.tokenValue).isEqualTo("createdTokenId")
    }

    @Test
    fun `generate when access token is not exists`() {
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequest: OAuth2TokenRequest = mockk()
        val createdAccessToken: OAuth2AuthorizedAccessToken = mockk(relaxed = true) {
            every { tokenId } returns OAuth2TokenId("createdTokenId")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
            every { composeUniqueKey } returns OAuth2ComposeUniqueKey("composeUniqueKey")
        }

        every { tokenRepository.findByComposeUniqueKey(OAuth2ComposeUniqueKey("composeUniqueKey")) } returns Optional.empty()
        Mockito.`when`(granter.createAccessToken(clientDetails, tokenRequest)).thenReturn(createdAccessToken)

        val result = granter.grant(clientDetails, tokenRequest)
        verify(exactly = 0) { tokenRepository.delete(any()) }
        verifyOrder {
            createdAccessToken.generateComposeUniqueKey(composeUniqueKeyGenerator)
            tokenRepository.findByComposeUniqueKey(OAuth2ComposeUniqueKey("composeUniqueKey"))
            tokenEnhancer.enhance(createdAccessToken)
            tokenRepository.save(createdAccessToken)
        }
        assertThat(result.tokenValue).isEqualTo("createdTokenId")
    }
}