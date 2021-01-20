package cube8540.oauth.authentication.credentials.oauth.security.endpoint

import cube8540.oauth.authentication.credentials.oauth.AuthorizationResponseKey
import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AuthorizationCodeGenerator
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import org.springframework.web.servlet.ModelAndView

class AuthorizationCodeResponseEnhancer(private val codeGenerator: OAuth2AuthorizationCodeGenerator, var nextEnhancer: AuthorizationResponseEnhancer?): AuthorizationResponseEnhancer {

    constructor(codeGenerator: OAuth2AuthorizationCodeGenerator): this(codeGenerator, null)

    override fun setNext(handler: AuthorizationResponseEnhancer): AuthorizationResponseEnhancer {
        this.nextEnhancer = handler
        return this
    }

    override fun enhance(modelAndView: ModelAndView, request: AuthorizationRequest): ModelAndView {
        if (request.responseType?.equals(OAuth2AuthorizationResponseType.CODE) == true) {
            val code = codeGenerator.generateNewAuthorizationCode(request)
            modelAndView.addObject(AuthorizationResponseKey.CODE, code.value)

            if (request.state != null) {
                modelAndView.addObject(AuthorizationResponseKey.STATE, request.state!!)
            }
        }

        return nextEnhancer?.enhance(modelAndView, request) ?: modelAndView
    }
}