package cube8540.oauth.authentication.credentials.resource.infra

import cube8540.oauth.authentication.credentials.AuthorityDetailsService
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceValidatorFactory
import cube8540.validator.core.Validator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Component

@Component
class DefaultSecuredResourceValidatorFactory: SecuredResourceValidatorFactory {

    @set:[Autowired Qualifier("defaultScopeDetailsService")]
    lateinit var scopeAuthorityDetailsService: AuthorityDetailsService

    override fun createValidator(resource: SecuredResource): Validator<SecuredResource> =
        Validator.of(resource)
            .registerRule(SecuredResourceIdRule())
            .registerRule(SecuredResourceRule())
            .registerRule(SecuredResourceAuthoritiesRule(scopeAuthorityDetailsService))
}