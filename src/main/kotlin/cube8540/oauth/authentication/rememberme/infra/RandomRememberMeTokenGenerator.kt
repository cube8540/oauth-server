package cube8540.oauth.authentication.rememberme.infra

import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenGenerator
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenSeries
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenValue
import java.security.SecureRandom
import java.util.Base64

class RandomRememberMeTokenGenerator(private val seriesLength: Int, private val tokenLength: Int): RememberMeTokenGenerator {

    companion object {
        const val DEFAULT_SERIES_LENGTH = 16
        const val DEFAULT_TOKEN_LENGTH = 16
    }

    private val random = SecureRandom()

    constructor(): this(DEFAULT_SERIES_LENGTH, DEFAULT_TOKEN_LENGTH)

    override fun generateTokenSeries(): RememberMeTokenSeries {
        val bytes = ByteArray(seriesLength)
        random.nextBytes(bytes)

        return RememberMeTokenSeries(String(Base64.getEncoder().encode(bytes)))
    }

    override fun generateTokenValue(): RememberMeTokenValue {
        val bytes = ByteArray(tokenLength)
        random.nextBytes(bytes)

        return RememberMeTokenValue(String(Base64.getEncoder().encode(bytes)))
    }
}