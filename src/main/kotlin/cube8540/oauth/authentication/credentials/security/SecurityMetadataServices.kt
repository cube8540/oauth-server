package cube8540.oauth.authentication.credentials.security

import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource
import org.springframework.security.web.util.matcher.RequestMatcher

data class RoleSecurityConfig(val config: String): SecurityConfig(config)

data class ScopeSecurityConfig(val config: String): SecurityConfig(config)

class TypeBasedAuthorityVoter(private val attributeType: Class<out SecurityConfig>): RoleVoter() {

    override fun supports(attribute: ConfigAttribute): Boolean =
        attributeType.isAssignableFrom(attribute.javaClass)
}

interface ReloadableFilterInvocationSecurityMetadataSource: FilterInvocationSecurityMetadataSource {
    fun reload()
}

interface SecurityMetadataLoadService {
    fun loadSecurityMetadata(): Map<RequestMatcher, Collection<ConfigAttribute>>
}