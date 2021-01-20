package cube8540.oauth.authentication.credentials.oauth.security.endpoint

import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails
import org.springframework.web.servlet.ModelAndView


interface AuthorizationResponseEnhancer {
    fun setNext(handler: AuthorizationResponseEnhancer): AuthorizationResponseEnhancer

    fun enhance(modelAndView: ModelAndView, request: AuthorizationRequest): ModelAndView
}

interface OAuth2AccessTokenIntrospectionConverter {
    fun convertAccessToken(accessToken: OAuth2AccessTokenDetails): Map<String, Any?>
}