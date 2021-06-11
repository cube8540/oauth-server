package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.AccessTokenIntrospectionKey
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails

class DefaultOAuth2AccessTokenIntrospectionConverter: OAuth2AccessTokenIntrospectionConverter {

    override fun convertAccessToken(accessToken: OAuth2AccessTokenDetails): Map<String, Any?> {
        val result: MutableMap<String, Any?> = HashMap()

        result[AccessTokenIntrospectionKey.ACTIVE] = !accessToken.expired
        result[AccessTokenIntrospectionKey.SCOPE] = accessToken.scopes?.joinToString(" ")

        return result
    }
}