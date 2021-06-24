package cube8540.oauth.authentication.user.application

import cube8540.oauth.authentication.users.application.DefaultUserApprovalAuthorityService
import cube8540.oauth.authentication.users.domain.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verifyOrder
import java.util.Optional
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class DefaultUserApprovalAuthorityServiceTest {
    private val repository: UserRepository = mockk()
    private val validatorFactory: UserValidatorFactory = mockk()
    private val service = DefaultUserApprovalAuthorityService(repository)

    init {
        every { repository.save(any()) } returnsArgument 0
        service.validatorFactory = validatorFactory
    }

    @Nested
    inner class GetApprovalAuthoritiesTest {

        @Test
        fun `request user is not registered in repository`() {
            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.getApprovalAuthorities("username") }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `request user is registered in repository`() {
            val userApprovalAuthorities = mutableSetOf(
                ApprovalAuthority("clientA", "SCOPE-1"),
                ApprovalAuthority("clientB", "SCOPE-2"),
                ApprovalAuthority("clientC", "SCOPE-3")
            )
            val user: User = mockk {
                every { approvalAuthorities } returns userApprovalAuthorities
            }

            every { repository.findById(Username("username")) } returns Optional.of(user)

            val result = service.getApprovalAuthorities("username")
            assertThat(result).isEqualTo(userApprovalAuthorities)
        }
    }

    @Nested
    inner class GrantApprovalAuthorityTest {

        @Test
        fun `request user is not registered in repository`() {
            val requestApprovalAuthorities: Collection<ApprovalAuthority> = listOf(
                ApprovalAuthority("clientA", "SCOPE-1"),
                ApprovalAuthority("clientB", "SCOPE-2"),
                ApprovalAuthority("clientC", "SCOPE-3")
            )

            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.grantApprovalAuthorities("username", requestApprovalAuthorities) }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `request user is registered in repository`() {
            val requestApprovalAuthorities: Collection<ApprovalAuthority> = listOf(
                ApprovalAuthority("clientA", "SCOPE-1"),
                ApprovalAuthority("clientB", "SCOPE-2"),
                ApprovalAuthority("clientC", "SCOPE-3")
            )
            val user: User = mockk(relaxed = true)

            every { repository.findById(Username("username")) } returns Optional.of(user)

            service.grantApprovalAuthorities("username", requestApprovalAuthorities)
            verifyOrder {
                user.addApprovalAuthority("clientA", "SCOPE-1")
                user.addApprovalAuthority("clientB", "SCOPE-2")
                user.addApprovalAuthority("clientC", "SCOPE-3")
                user.validation(validatorFactory)
                repository.save(user)
            }
        }
    }

    @Nested
    inner class RevokeApprovalAuthorityTest {

        @Test
        fun `request user is not registered in repository`() {
            val requestApprovalAuthorities: Collection<ApprovalAuthority> = listOf(
                ApprovalAuthority("clientA", "SCOPE-1"),
                ApprovalAuthority("clientB", "SCOPE-2"),
                ApprovalAuthority("clientC", "SCOPE-3")
            )

            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.revokeApprovalAuthorities("username", requestApprovalAuthorities) }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `request user is registered in repository`() {
            val requestApprovalAuthorities: Collection<ApprovalAuthority> = listOf(
                ApprovalAuthority("clientA", "SCOPE-1"),
                ApprovalAuthority("clientB", "SCOPE-2"),
                ApprovalAuthority("clientC", "SCOPE-3")
            )
            val user: User = mockk(relaxed = true)

            every { repository.findById(Username("username")) } returns Optional.of(user)

            service.revokeApprovalAuthorities("username", requestApprovalAuthorities)
            verifyOrder {
                user.revokeApprovalAuthority("clientA", "SCOPE-1")
                user.revokeApprovalAuthority("clientB", "SCOPE-2")
                user.revokeApprovalAuthority("clientC", "SCOPE-3")
                repository.save(user)
            }
        }
    }
}