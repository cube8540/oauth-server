package cube8540.oauth.authentication.security

import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.http.HttpServletRequest

class UriSecurityMetadataSourceTest {
    private val pool = ('a'..'z').map { it.toString() }

    private val metadataLoadService: SecurityMetadataLoadService = mockk(relaxed = true)

    @Nested
    inner class InitializationTest {
        private val metadata: Map<RequestMatcher, Collection<ConfigAttribute>> = hashMapOf(
            mockk<RequestMatcher>(relaxed = true) to listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random())),
            mockk<RequestMatcher>(relaxed = true) to listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random())),
            mockk<RequestMatcher>(relaxed = true) to listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random()))
        )

        init {
            every { metadataLoadService.loadSecurityMetadata() } returns metadata
        }

        @Test
        fun `initialize metadata`() {
            val metadataSource = UriSecurityMetadataSource(metadataLoadService)

            val result = metadataSource.metadata
            assertThat(result).isEqualTo(metadata)
        }
    }

    @Nested
    inner class GetAllAttributeTest {
        private val requestMatcherA = AntPathRequestMatcher(pool.random())
        private val metadataA = listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random()), SecurityConfig(pool.random()))

        private val requestMatcherB = AntPathRequestMatcher(pool.random())
        private val metadataB = listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random()), SecurityConfig(pool.random()))

        private val requestMatcherC = AntPathRequestMatcher(pool.random())
        private val metadataC = listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random()), SecurityConfig(pool.random()))

        private val metadata: Map<RequestMatcher, Collection<ConfigAttribute>> = hashMapOf(
            requestMatcherA to metadataA,
            requestMatcherB to metadataB,
            requestMatcherC to metadataC
        )

        init {
            every { metadataLoadService.loadSecurityMetadata() } returns metadata
        }

        @Test
        fun `return all metadata`() {
            val metadataSource = UriSecurityMetadataSource(metadataLoadService)

            val result = metadataSource.allConfigAttributes
            val expected = (metadataA + metadataB + metadataC).toSet()

            assertThat(result).isEqualTo(expected)
        }
    }

    @Nested
    inner class GetAccessibleAttributeTest {
        private val requestMatcherA: RequestMatcher = mockk()
        private val metadataAttributeA = listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random()), SecurityConfig(pool.random()))

        private val requestMatcherB: RequestMatcher = mockk()
        private val metadataAttributeB = listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random()), SecurityConfig(pool.random()))

        private val requestMatcherC: RequestMatcher = mockk()
        private val metadataAttributeC = listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random()), SecurityConfig(pool.random()))

        init {
            every { metadataLoadService.loadSecurityMetadata() } returns hashMapOf(
                requestMatcherA to metadataAttributeA,
                requestMatcherB to metadataAttributeB,
                requestMatcherC to metadataAttributeC
            )
        }

        @Test
        fun `accessible metadata not found`() {
            val servletRequest: HttpServletRequest = mockk()
            val invocation: FilterInvocation = mockk {
                every { request } returns servletRequest
            }
            val metadataSource = UriSecurityMetadataSource(metadataLoadService)

            every { requestMatcherA.matches(servletRequest) } returns false
            every { requestMatcherB.matches(servletRequest) } returns false
            every { requestMatcherC.matches(servletRequest) } returns false

            val result = metadataSource.getAttributes(invocation)
            assertThat(result).isEmpty()
        }

        @Test
        fun `get accessible metadata`() {
            val servletRequest: HttpServletRequest = mockk()
            val invocation: FilterInvocation = mockk {
                every { request } returns servletRequest
            }
            val metadataSource = UriSecurityMetadataSource(metadataLoadService)

            every { requestMatcherA.matches(servletRequest) } returns true
            every { requestMatcherB.matches(servletRequest) } returns true
            every { requestMatcherC.matches(servletRequest) } returns true

            val result = metadataSource.getAttributes(invocation)
            val excepted = (metadataAttributeA + metadataAttributeB + metadataAttributeC).toSet()
            assertThat(result).isEqualTo(excepted)
        }
    }

    @Nested
    inner class ReloadTest {
        private val metadata: Map<RequestMatcher, Collection<ConfigAttribute>> = hashMapOf(
            mockk<RequestMatcher>(relaxed = true) to listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random()))
        )
        private val reloadMetadata: Map<RequestMatcher, Collection<ConfigAttribute>> = hashMapOf(
            mockk<RequestMatcher>(relaxed = true) to listOf(SecurityConfig(pool.random()), SecurityConfig(pool.random()))
        )

        init {
            every { metadataLoadService.loadSecurityMetadata() } returns metadata
        }

        @Test
        fun `reload metadata`() {
            val metadataSource = UriSecurityMetadataSource(metadataLoadService)

            every { metadataLoadService.loadSecurityMetadata() } returns reloadMetadata

            metadataSource.reload()
            assertThat(metadataSource.metadata).isEqualTo(reloadMetadata)
        }
    }

    @Nested
    inner class CheckSupportTest {

        @Test
        fun `check supported class`() {
            val metadataSource = UriSecurityMetadataSource(metadataLoadService)

            val result = metadataSource.supports(FilterInvocation::class.java)
            assertThat(result).isTrue
        }
    }
}