package cube8540.oauth.authentication.credentials.resource.infra

import cube8540.oauth.authentication.credentials.AuthorityDetailsService
import cube8540.oauth.authentication.credentials.resource.domain.AccessibleAuthority
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource
import cube8540.validator.core.ValidationError
import cube8540.validator.core.ValidationRule
import java.util.*
import java.util.stream.Collectors

class SecuredResourceIdRule(val property: String, val message: String): ValidationRule<SecuredResource> {

    companion object {
        const val DEFAULT_PROPERTY = "resourceId"
        const val DEFAULT_MESSAGE = "자원 아이디를 입력해 주세요."
    }

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: SecuredResource): Boolean =
        target.resourceId.value.isNotEmpty()

    override fun error(): ValidationError = ValidationError(property, message)

}

class SecuredResourceRule(val property: String, val message: String): ValidationRule<SecuredResource> {

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
    val property: String,
    val message: String,
    private val scopeDetailsService: AuthorityDetailsService
): ValidationRule<SecuredResource> {

    companion object {
        const val DEFAULT_PROPERTY = "authorities"
        const val DEFAULT_MESSAGE = "부여할 수 없는 권한 입니다."
    }

    constructor(scopeDetailsService: AuthorityDetailsService): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE, scopeDetailsService)

    override fun isValid(target: SecuredResource): Boolean {
        val targetScopes = target.authorities?.stream()
            ?.map { auth -> auth.authority }?.collect(Collectors.toSet())?: Collections.emptyList()

        if (targetScopes.isEmpty()) {
            return true
        }

        return scopeDetailsService.loadAuthorityByAuthorityCodes(targetScopes).stream()
            .map { auth -> auth.code }.collect(Collectors.toList())
            .containsAll(targetScopes)
    }

    override fun error(): ValidationError = ValidationError(property, message)
}