package cube8540.oauth.authentication.oauth.client.infra

import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.security.AuthorityDetails
import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client
import cube8540.oauth.authentication.oauth.scope.application.OAuth2ScopeManagementService
import cube8540.validator.core.ValidationError
import cube8540.validator.core.ValidationRule
import java.util.regex.Pattern
import java.util.stream.Collectors

class DefaultClientIdValidationRule(private val property: String, private val message: String): ValidationRule<OAuth2Client> {

    companion object {
        private const val WHITELIST_PATTERN_VALUE = "^[_\\-a-zA-Z0-9]+$"

        private const val DEFAULT_PROPERTY = "clientId"
        private const val DEFAULT_MESSAGE = "아이디는 8 ~ 30글자 사이의 문자열로 입력해 주세요. (특수문자는 '-', '_' 만 가능합니다.)"
    }

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: OAuth2Client): Boolean {
        val clientId = target.clientId.value

        return clientId.length in 8..30 && Pattern.compile(WHITELIST_PATTERN_VALUE).matcher(clientId).matches()
    }

    override fun error(): ValidationError = ValidationError(property, message)
}

class DefaultClientGrantTypeValidationRule(private val property: String, private val message: String): ValidationRule<OAuth2Client> {

    companion object {
        private const val DEFAULT_PROPERTY = "grantType"
        private const val DEFAULT_MESSAGE = "클라이언트의 인증 타입은 한개 이상이어야 합니다."
    }

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: OAuth2Client): Boolean = target.grantTypes != null && target.grantTypes!!.isNotEmpty()

    override fun error(): ValidationError = ValidationError(property, message)
}

class DefaultClientNameValidationRule(private val property: String, private val message: String): ValidationRule<OAuth2Client> {

    companion object {
        private const val DEFAULT_PROPERTY = "clientName"
        private const val DEFAULT_MESSAGE = "클라이언트명을 입력해 주세요."
    }

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: OAuth2Client): Boolean = target.clientName != null

    override fun error(): ValidationError = ValidationError(property, message)
}

class DefaultOAuth2ClientOwnerValidationRule(private val property: String, private val message: String): ValidationRule<OAuth2Client> {

    companion object {
        private const val DEFAULT_PROPERTY = "owner"
        private const val DEFAULT_MESSAGE = "클라이언트의 소유자를 입력해 주세요."
    }

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: OAuth2Client): Boolean = target.owner != null

    override fun error(): ValidationError = ValidationError(property, message)

}

class ClientCanGrantedScopeValidationRule(private val property: String, private val message: String): ValidationRule<OAuth2Client> {

    var scopeDetailsService: OAuth2ScopeManagementService? = null

    companion object {
        const val DEFAULT_PROPERTY = "scope"
        const val DEFAULT_MESSAGE = "부여할 수 없는 스코프 입니다."
    }

    constructor(): this(DEFAULT_PROPERTY, DEFAULT_MESSAGE)

    override fun isValid(target: OAuth2Client): Boolean {
        if (scopeDetailsService == null) {
            return false
        }
        if (target.scopes == null || target.scopes!!.isEmpty()) {
            return false
        }
        val accessibleScopes = scopeDetailsService!!.loadScopes()
            .map(AuthorityDetails::code).map { AuthorityCode(it) }.toSet()
        return accessibleScopes.containsAll(target.scopes!!)
    }

    override fun error(): ValidationError = ValidationError(property, message)
}