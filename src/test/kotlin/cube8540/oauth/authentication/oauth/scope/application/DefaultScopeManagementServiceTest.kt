package cube8540.oauth.authentication.oauth.scope.application

import cube8540.oauth.authentication.oauth.scope.domain.OAuth2Scope
import cube8540.oauth.authentication.oauth.scope.domain.OAuth2ScopeRepository
import cube8540.oauth.authentication.oauth.scope.domain.ScopeNotFoundException
import cube8540.oauth.authentication.oauth.scope.domain.ScopeRegisterException
import cube8540.oauth.authentication.security.AuthorityCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import io.mockk.verifyOrder
import java.util.Optional
import kotlin.random.Random
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class DefaultScopeManagementServiceTest {

    private val repository: OAuth2ScopeRepository = mockk(relaxed = true)

    private val service = OAuth2ApplicationScopeService(repository)

    init {
        every { repository.save(any()) } returnsArgument 0
    }

    @Nested
    inner class CountingScope {

        @Test
        fun `counting authority code`() {
            val randomCount = Random.nextLong()

            every { repository.countByCode(AuthorityCode("scopeId")) } returns randomCount

            val result = service.countByScopeId("scopeId")
            assertThat(result).isEqualTo(randomCount)
        }
    }

    @Nested
    inner class RegisterNewScope {

        @Test
        fun `scope is already registered in repository`() {
            val registerRequest = OAuth2ScopeRegisterRequest("scopeId", "desc")

            every { repository.countByCode(AuthorityCode("scopeId")) } returns 1

            val thrown = catchThrowable { service.registerNewScope(registerRequest) }
            assertThat(thrown).isInstanceOf(ScopeRegisterException::class.java)
        }

        @Test
        fun `register successful`() {
            val scopeCaptor = slot<OAuth2Scope>()
            val registerRequest = OAuth2ScopeRegisterRequest("scopeId", "desc")

            every { repository.countByCode(AuthorityCode("scopeId")) } returns 0
            every { repository.save(capture(scopeCaptor)) } returnsArgument 0

            service.registerNewScope(registerRequest)
            assertThat(scopeCaptor.isCaptured).isTrue
            assertThat(scopeCaptor.captured.code).isEqualTo(AuthorityCode("scopeId"))
            assertThat(scopeCaptor.captured.description).isEqualTo("desc")
            assertThat(scopeCaptor.captured.initialize).isFalse
        }
    }

    @Nested
    inner class ModifyScope {

        @Test
        fun `scope is not registered in repository`() {
            val modifyRequest = OAuth2ScopeModifyRequest("modify desc")

            every { repository.findById(AuthorityCode("scopeId")) } returns Optional.empty()

            val thrown = catchThrowable { service.modifyScope("scopeId", modifyRequest) }
            assertThat(thrown).isInstanceOf(ScopeNotFoundException::class.java)
        }

        @Test
        fun `modify is successful`() {
            val savedScope = slot<OAuth2Scope>()
            val storedScope: OAuth2Scope = mockk(relaxed = true)
            val modifyRequest = OAuth2ScopeModifyRequest("modify desc")

            every { repository.findById(AuthorityCode("scopeId")) } returns Optional.of(storedScope)

            service.modifyScope("scopeId", modifyRequest)
            verifyOrder {
                storedScope.description = "modify desc"
                repository.save(capture(savedScope))
            }
            assertThat(savedScope.captured).isEqualTo(storedScope)
        }
    }

    @Nested
    inner class RemoveScope {

        @Test
        fun `scope is not registered in repository`() {
            every { repository.findById(AuthorityCode("scopeId")) } returns Optional.empty()

            val thrown = catchThrowable { service.removeScope("scopeId") }
            assertThat(thrown).isInstanceOf(ScopeNotFoundException::class.java)
        }

        @Test
        fun `remove successful`() {
            val removedScope = slot<OAuth2Scope>()
            val storedScope: OAuth2Scope = mockk(relaxed = true)

            every { repository.findById(AuthorityCode("scopeId")) } returns Optional.of(storedScope)

            service.removeScope("scopeId")
            verify { repository.delete(capture(removedScope)) }
            assertThat(removedScope.captured).isEqualTo(storedScope)
        }
    }
}