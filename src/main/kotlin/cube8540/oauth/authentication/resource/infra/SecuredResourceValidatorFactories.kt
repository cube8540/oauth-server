package cube8540.oauth.authentication.resource.infra

import cube8540.oauth.authentication.security.AuthorityDetailsService
import cube8540.oauth.authentication.resource.domain.SecuredResource
import cube8540.oauth.authentication.resource.domain.SecuredResourceValidatorFactory
import io.github.cube8540.validator.core.Validator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Component

@Component
class DefaultSecuredResourceValidatorFactory: SecuredResourceValidatorFactory {

    @set:Autowired
    lateinit var scopeAuthorityDetailsService: AuthorityDetailsService

    override fun createValidator(resource: SecuredResource): Validator<SecuredResource> =
        Validator.of(resource)
            .registerRule(SecuredResourceIdRule())
            .registerRule(SecuredResourceRule())
            .registerRule(SecuredResourceAuthoritiesRule(scopeAuthorityDetailsService))
}