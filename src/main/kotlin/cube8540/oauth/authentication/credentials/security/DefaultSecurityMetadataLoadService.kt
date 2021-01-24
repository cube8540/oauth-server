package cube8540.oauth.authentication.credentials.security

import cube8540.oauth.authentication.credentials.resource.domain.AccessibleAuthority
import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceRepository
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.stereotype.Service
import java.util.*
import java.util.function.Function
import java.util.stream.Collectors

@Service
class DefaultSecurityMetadataLoadService(private val repository: SecuredResourceRepository): SecurityMetadataLoadService {

    private val keyGenerator = Function { resource: SecuredResource -> requestMatcher(resource) }

    private val valueGenerator = Function { resource: SecuredResource -> authorityToConfigAttribute(resource.authorities) }

    override fun loadSecurityMetadata(): Map<RequestMatcher, Collection<ConfigAttribute>> =
        repository.findAll().stream().collect(Collectors.toMap(keyGenerator, valueGenerator))

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

        authorities?.forEach { authority -> configAttributes.add(ScopeSecurityConfig(authority.authority)) }

        return configAttributes
    }
}