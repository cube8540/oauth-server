package cube8540.oauth.authentication.oauth.token.infra

import cube8540.oauth.authentication.oauth.token.domain.AuthorizationCodeGenerator
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2ComposeUniqueKey
import cube8540.oauth.authentication.oauth.token.domain.OAuth2ComposeUniqueKeyGenerator
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenId
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator
import cube8540.oauth.authentication.security.AuthorityCode
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.util.Random
import java.util.UUID
import org.springframework.stereotype.Component

@Component
class DefaultTokenIdGenerator: OAuth2TokenIdGenerator {
    override fun generateTokenValue(): OAuth2TokenId =
        OAuth2TokenId(UUID.randomUUID().toString().replace("-", ""))
}

@Component
class DefaultAuthorizationCodeGenerator(private val keyLength: Int): AuthorizationCodeGenerator {

    companion object {
        private val DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray()
    }

    private val random: Random = SecureRandom()

    constructor(): this(6)

    override fun generate(): String {
        val bytes = ByteArray(keyLength)
        random.nextBytes(bytes)
        return getRandomCode(bytes)
    }

    private fun getRandomCode(bytes: ByteArray): String {
        val chars = CharArray(bytes.size)
        for (i in bytes.indices) {
            chars[i] = DEFAULT_CODEC[(bytes[i].toInt() and 0xFF) % DEFAULT_CODEC.size]
        }
        return String(chars)
    }
}

@Component
class WithScopeComposeUniqueKeyGenerator: OAuth2ComposeUniqueKeyGenerator {

    companion object {
        internal const val USERNAME_KEY = "username"
        internal const val CLIENT_KEY = "clientId"
        internal const val SCOPE_KEY = "scopes"
    }

    override fun generateKey(token: OAuth2AuthorizedAccessToken): OAuth2ComposeUniqueKey {
        val values = LinkedHashMap<String, String?>()
        if (token.username != null) {
            values[USERNAME_KEY] = token.username!!.value
        }
        values[CLIENT_KEY] = token.client.value
        values[SCOPE_KEY] = token.scopes.map(AuthorityCode::value).sorted().toList().toString()

        try {
            val digest = MessageDigest.getInstance("MD5")
            val bytes = digest.digest(values.toString().toByteArray(StandardCharsets.UTF_8))
            return OAuth2ComposeUniqueKey(String.format("%032x", BigInteger(1, bytes)))
        } catch (exception: NoSuchAlgorithmException) {
            throw IllegalArgumentException(exception)
        }
    }
}