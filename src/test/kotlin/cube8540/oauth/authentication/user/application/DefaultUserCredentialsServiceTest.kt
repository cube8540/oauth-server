package cube8540.oauth.authentication.user.application

import cube8540.oauth.authentication.users.application.DefaultUserCredentialsService
import cube8540.oauth.authentication.users.domain.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verifyOrder
import java.util.Optional
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class DefaultUserCredentialsServiceTest {

    private val repository: UserRepository = mockk(relaxed = true)
    private val keyGenerator: UserCredentialsKeyGenerator = mockk()
    private val service = DefaultUserCredentialsService(repository)

    init {
        service.keyGenerator = keyGenerator
        every { repository.save(any()) } returnsArgument 0
    }

    @Nested
    inner class GrantCredentialsKeyTest {

        @Test
        fun `request user is not registered in repository`() {
            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.grantCredentialsKey("username") }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `request user is registered in repository`() {
            val user: User = mockk(relaxed = true)

            every { repository.findById(Username("username")) } returns Optional.of(user)

            service.grantCredentialsKey("username")
            verifyOrder {
                user.generateCredentialsKey(keyGenerator)
                repository.save(user)
            }
        }
    }

    @Nested
    inner class CredentialsTest {

        @Test
        fun `request user is not registered in repository`() {
            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.accountCredentials("username", "key") }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `request user is registered in repository`() {
            val user: User = mockk(relaxed = true)

            every { repository.findById(Username("username")) } returns Optional.of(user)

            service.accountCredentials("username", "key")
            verifyOrder {
                user.credentials("key")
                repository.save(user)
            }
        }
    }
}