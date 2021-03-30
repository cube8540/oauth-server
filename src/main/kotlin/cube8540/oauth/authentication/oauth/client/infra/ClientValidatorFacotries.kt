package cube8540.oauth.authentication.oauth.client.infra

import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientValidatorFactory
import cube8540.oauth.authentication.oauth.scope.application.OAuth2ScopeManagementService
import cube8540.validator.core.Validator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Component

@Component
class DefaultOAuth2ClientValidatorFactory: OAuth2ClientValidatorFactory {

    @set:[Autowired Qualifier("defaultScopeManagementService")]
    lateinit var scopeDetailsService: OAuth2ScopeManagementService

    override fun createValidator(client: OAuth2Client): Validator<OAuth2Client> {
        val scopeRule = ClientCanGrantedScopeValidationRule()
        scopeRule.scopeDetailsService = scopeDetailsService

        return Validator.of(client).registerRule(DefaultClientIdValidationRule())
            .registerRule(DefaultOAuth2ClientOwnerValidationRule())
            .registerRule(DefaultClientNameValidationRule())
            .registerRule(DefaultClientGrantTypeValidationRule())
            .registerRule(scopeRule)
    }
}