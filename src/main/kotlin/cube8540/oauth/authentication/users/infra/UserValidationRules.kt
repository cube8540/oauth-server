package cube8540.oauth.authentication.users.infra

import cube8540.oauth.authentication.oauth.error.OAuth2ClientRegistrationException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService
import cube8540.oauth.authentication.users.domain.User
import io.github.cube8540.validator.core.ValidationError
import io.github.cube8540.validator.core.ValidationRule
import java.util.regex.Pattern

class DefaultUsernameValidationRule(private val property: String, private val message: String): ValidationRule<User> {

    companion object {
        private const val REQUIRED_PATTERN_VALUE = "^(?=.*?[a-z])(?=.*?[0-9]).{4,18}$"
        private const val WHITELIST_PATTERN_VALUE = "^[A-Za-z0-9]{4,18}$"

        private const val DEFAULT_PROPERTY = "username"
        private const val DEFAULT_MESSAGE = "아이디는 영문과 숫자를 조합한 4 ~ 18 글자로 입력해 주세요."
    }

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: User): Boolean =
        matchesRequiredPattern(target.username.value) && matchesWhitelistPattern(target.username.value)

    override fun error(): ValidationError = ValidationError(property, message)

    private fun matchesRequiredPattern(username: String): Boolean =
        Pattern.compile(REQUIRED_PATTERN_VALUE).matcher(username).matches()

    private fun matchesWhitelistPattern(username: String): Boolean =
        Pattern.compile(WHITELIST_PATTERN_VALUE).matcher(username).matches()
}

class DefaultUserPasswordValidationRule(private val property: String, private val message: String): ValidationRule<User> {

    companion object {
        private const val REQUIRED_PATTERN_VALUE = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{12,30}$"
        private const val WHITELIST_PATTERN_VALUE = "^[#?!@$%^&*\\-a-zA-Z0-9 ]+$"

        private const val DEFAULT_PROPERTY = "password"
        private const val DEFAULT_MESSAGE = "패스워드는 특수문자(#?!@$%^&*)와 대소문자, 숫자 조합으로 12 ~ 30 글자로 입력해야 합니다."
    }

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: User): Boolean =
        matchesRequiredPattern(target.password) && matchesWhitelistPattern(target.password)

    override fun error(): ValidationError = ValidationError(property, message)

    private fun matchesRequiredPattern(password: String): Boolean =
        Pattern.compile(REQUIRED_PATTERN_VALUE).matcher(password).matches()

    private fun matchesWhitelistPattern(password: String): Boolean =
        Pattern.compile(WHITELIST_PATTERN_VALUE).matcher(password).matches()
}

class DefaultApprovalAuthorityValidationRule(private val property: String, private val message: String): ValidationRule<User> {

    companion object {
        private const val DEFAULT_PROPERTY = "approvalAuthority"
        private const val DEFAULT_MESSAGE = "포함할 수 없는 권한 입니다."
    }

    var clientDetailsService: OAuth2ClientDetailsService? = null

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: User): Boolean {
        if (this.clientDetailsService == null) {
            return false
        }
        if (target.approvalAuthorities == null || target.approvalAuthorities!!.isEmpty()) {
            return true
        }
        return try {
            target.approvalAuthorities!!
                .groupBy(keySelector = { it.clientId }, valueTransform = { it.scopeId })
                .map { (clientId, scopes) ->
                    clientDetailsService!!.loadClientDetailsByClientId(clientId).scopes.containsAll(scopes)
                }
                .all { it }
        } catch (e: OAuth2ClientRegistrationException) {
            false
        }
    }

    override fun error(): ValidationError = ValidationError(property, message)

}