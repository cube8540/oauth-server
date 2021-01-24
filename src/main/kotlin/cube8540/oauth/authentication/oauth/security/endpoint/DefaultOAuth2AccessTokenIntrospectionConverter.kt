package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.AuthenticationApplication
import cube8540.oauth.authentication.oauth.AccessTokenIntrospectionKey
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import java.util.*

class DefaultOAuth2AccessTokenIntrospectionConverter: OAuth2AccessTokenIntrospectionConverter {

    override fun convertAccessToken(accessToken: OAuth2AccessTokenDetails): Map<String, Any?> {
        val result: MutableMap<String, Any?> = HashMap()

        result[AccessTokenIntrospectionKey.ACTIVE] = !accessToken.expired
        result[AccessTokenIntrospectionKey.CLIENT_ID] = accessToken.clientId
        result[AccessTokenIntrospectionKey.USERNAME] = accessToken.username
        result[AccessTokenIntrospectionKey.EXPIRATION] = accessToken.expiration
            .atZone(AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId()).toEpochSecond()
        result[AccessTokenIntrospectionKey.SCOPE] = accessToken.scopes?.joinToString(" ")

        return result
    }
}