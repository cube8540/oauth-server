package cube8540.oauth.authentication.oauth.security.introspector

import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetailsService
import cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenNotFoundException
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector

class DefaultAccessTokenIntrospector(private val accessTokenService: OAuth2AccessTokenDetailsService, private val authenticationProvider: AuthenticationProvider): OpaqueTokenIntrospector {

    var clientId: String? = null

    var clientSecret: String? = null

    override fun introspect(token: String): OAuth2AuthenticatedPrincipal {
        val accessToken = readAccessToken(token)

        val clientCredentials = clientAuthentication(clientId!!, clientSecret!!)
        if (clientCredentials.name != accessToken.clientId) {
            throw OAuth2IntrospectionException("Client is different")
        }
        return DefaultOAuth2AuthenticatedPrincipal(accessToken.username, convertClaims(accessToken), extractAuthorities(accessToken))
    }

    private fun readAccessToken(token: String): OAuth2AccessTokenDetails {
        try {
            val accessToken = accessTokenService.readAccessToken(token)
            if (accessToken.expired) {
                throw OAuth2IntrospectionException("$token is not active")
            }
            return accessToken
        } catch (e: OAuth2AccessTokenNotFoundException) {
            throw OAuth2IntrospectionException("$token is not active", e)
        }
    }

    private fun convertClaims(accessToken: OAuth2AccessTokenDetails): Map<String, *> {
        val claims = HashMap<String, Any?>()

        if (accessToken.clientId != null) {
            claims[OAuth2IntrospectionClaimNames.CLIENT_ID] = accessToken.clientId!!
        }
        if (accessToken.scopes != null && accessToken.scopes!!.isNotEmpty()) {
            claims[OAuth2IntrospectionClaimNames.SCOPE] = extractAuthorities(accessToken)
        }
        if (accessToken.additionalInformation != null) {
            accessToken.additionalInformation!!.forEach { (key, value) -> claims[key] = value }
        }

        return claims
    }

    private fun extractAuthorities(accessToken: OAuth2AccessTokenDetails): Collection<GrantedAuthority> =
        accessToken.scopes?.map { SimpleGrantedAuthority(it) } ?: emptySet()

    private fun clientAuthentication(clientId: String, clientSecret: String): Authentication {
        try {
            return authenticationProvider.authenticate(ClientCredentialsToken(clientId, clientSecret))
        } catch (e: Exception) {
            throw OAuth2IntrospectionException("Bad client credentials", e)
        }
    }
}