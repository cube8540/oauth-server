package cube8540.oauth.authentication.security

import org.springframework.security.access.ConfigAttribute
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.stereotype.Component
import java.util.stream.Collectors

@Component
class UriSecurityMetadataSource(private val service: SecurityMetadataLoadService): ReloadableFilterInvocationSecurityMetadataSource {

    final var metadata: Map<RequestMatcher, Collection<ConfigAttribute>> = service.loadSecurityMetadata()
        private set

    override fun reload() {
        this.metadata = service.loadSecurityMetadata()
    }

    override fun getAttributes(`object`: Any?): MutableCollection<ConfigAttribute> {
        val request = (`object` as FilterInvocation).request

        return metadata.entries
            .filter { it.key.matches(request) }
            .map { it.value }
            .flatMap { it.asIterable() }
            .toMutableSet()
    }

    override fun getAllConfigAttributes(): MutableCollection<ConfigAttribute> =
        metadata.values
            .flatMap { it.asIterable() }
            .toMutableSet()

    override fun supports(clazz: Class<*>): Boolean = FilterInvocation::class.java.isAssignableFrom(clazz)
}