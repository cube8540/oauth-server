package cube8540.oauth.authentication.rememberme.domain

interface RememberMeTokenGenerator {
    fun generateTokenSeries(): RememberMeTokenSeries

    fun generateTokenValue(): RememberMeTokenValue
}