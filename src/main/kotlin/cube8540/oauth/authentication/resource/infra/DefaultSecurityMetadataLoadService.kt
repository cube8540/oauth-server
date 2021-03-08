package cube8540.oauth.authentication.resource.infra

import cube8540.oauth.authentication.resource.domain.AccessibleAuthority
import cube8540.oauth.authentication.resource.domain.ResourceMethod
import cube8540.oauth.authentication.resource.domain.SecuredResource
import cube8540.oauth.authentication.resource.domain.SecuredResourceRepository
import cube8540.oauth.authentication.security.ScopeSecurityConfig
import cube8540.oauth.authentication.security.SecurityMetadataLoadService
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.stereotype.Service
import java.util.*

@Service
class DefaultSecurityMetadataLoadService(private val repository: SecuredResourceRepository):
    SecurityMetadataLoadService {

    override fun loadSecurityMetadata(): Map<RequestMatcher, Collection<ConfigAttribute>> =
        repository.findAll().map { requestMatcher(it) to authorityToConfigAttribute(it.authorities) }.toMap()

    private fun requestMatcher(securedResource: SecuredResource): RequestMatcher = when (securedResource.method) {
        ResourceMethod.ALL -> {
            AntPathRequestMatcher(securedResource.resource.toString())
        }
        else -> {
            AntPathRequestMatcher(securedResource.resource.toString(), securedResource.method.toString())
        }
    }

    private fun authorityToConfigAttribute(authorities: Set<AccessibleAuthority>?): Collection<ConfigAttribute> {
        val configAttributes = HashSet<ConfigAttribute>()

        authorities?.forEach { configAttributes.add(ScopeSecurityConfig(it.authority)) }

        return configAttributes
    }
}