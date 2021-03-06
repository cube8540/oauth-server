package cube8540.oauth.authentication.resource.infra

import cube8540.oauth.authentication.resource.domain.AccessibleAuthority
import cube8540.oauth.authentication.resource.domain.SecuredResource
import cube8540.oauth.authentication.security.AuthorityDetailsService
import io.github.cube8540.validator.core.ValidationError
import io.github.cube8540.validator.core.ValidationRule

class SecuredResourceIdRule(private val property: String, private val message: String): ValidationRule<SecuredResource> {

    companion object {
        const val DEFAULT_PROPERTY = "resourceId"
        const val DEFAULT_MESSAGE = "자원 아이디를 입력해 주세요."
    }

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: SecuredResource): Boolean =
        target.resourceId.value.isNotEmpty()

    override fun error(): ValidationError = ValidationError(property, message)
}

class SecuredResourceRule(private val property: String, private val message: String): ValidationRule<SecuredResource> {

    companion object {
        const val DEFAULT_PROPERTY = "resource"
        const val DEFAULT_MESSAGE = "자원을 입력해 주세요."
    }

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: SecuredResource): Boolean =
        target.resource.toString().isNotEmpty()


    override fun error(): ValidationError = ValidationError(property, message)
}

class SecuredResourceAuthoritiesRule(
    private val property: String,

    private val message: String,

    private val scopeDetailsService: AuthorityDetailsService
): ValidationRule<SecuredResource> {

    companion object {
        const val DEFAULT_PROPERTY = "authorities"
        const val DEFAULT_MESSAGE = "부여할 수 없는 권한 입니다."
    }

    constructor(scopeDetailsService: AuthorityDetailsService): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE, scopeDetailsService)

    override fun isValid(target: SecuredResource): Boolean {
        val targetScopes = target.authorities?.map(AccessibleAuthority::authority)?.toSet() ?: emptySet()
        if (targetScopes.isEmpty()) {
            return true
        }
        return scopeDetailsService.loadAuthorityByAuthorityCodes(targetScopes)
            .map { it.code }.toList().containsAll(targetScopes)
    }

    override fun error(): ValidationError = ValidationError(property, message)
}