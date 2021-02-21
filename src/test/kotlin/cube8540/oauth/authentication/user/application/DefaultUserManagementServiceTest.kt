package cube8540.oauth.authentication.user.application

import cube8540.oauth.authentication.error.message.ErrorCodes
import cube8540.oauth.authentication.users.application.DefaultUserManagementService
import cube8540.oauth.authentication.users.application.UserRegisterRequest
import cube8540.oauth.authentication.users.domain.*
import io.mockk.*
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.password.PasswordEncoder
import java.util.*
import kotlin.random.Random

class DefaultUserManagementServiceTest {
    private val repository: UserRepository = mockk(relaxed = true)
    private val passwordEncoder: PasswordEncoder = mockk()
    private val keyGenerator: UserCredentialsKeyGenerator = mockk()
    private val uidGenerator: UserUidGenerator = mockk()
    private val validatorFactory: UserValidatorFactory = mockk()

    private val service = DefaultUserManagementService(repository, passwordEncoder)

    init {
        service.keyGenerator = keyGenerator
        service.uidGenerator = uidGenerator
        service.validatorFactory = validatorFactory

        every { repository.save(any()) } returnsArgument 0
    }

    @Nested
    inner class CountingTest {

        @Test
        fun `user counting`() {
            val count = Random.nextLong(0, 100)

            every { repository.countByUsername(Username("username")) } returns count

            val results = service.countUser("username")
            assertThat(results).isEqualTo(count)
        }
    }

    @Nested
    inner class LoadProfileTest {

        @Test
        fun `request user is not registered in repository`() {
            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.loadUserProfile("username") }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `request user is registered in repository`() {
            val user: User = mockk(relaxed = true) {
                every { uid } returns Uid("uid")
                every { username } returns Username("username")
            }

            every { repository.findById(Username("username")) } returns Optional.of(user)

            val result = service.loadUserProfile("username")
            assertThat(result.uid).isEqualTo("uid")
            assertThat(result.username).isEqualTo("username")
        }
    }

    @Nested
    inner class RegisterNewUserTest {

        @Test
        fun `user is already registered in repository`() {
            val registerRequest = UserRegisterRequest("username", "password")

            every { repository.countByUsername(Username("username")) } returns 1

            val thrown = catchThrowable { service.registerUser(registerRequest) }
            assertThat(thrown).isInstanceOf(UserRegisterException::class.java)
            assertThat(((thrown) as UserRegisterException).code)
                .isEqualTo(ErrorCodes.EXISTS_IDENTIFIER)
        }

        @Test
        fun `request user data is invalid`() {
            val registerRequest = UserRegisterRequest("username", "password")

            every { uidGenerator.generateUid() } returns Uid("uid")
            every { repository.countByUsername(Username("username")) } returns 0
            every { validatorFactory.createValidator(any()) } returns mockk {
                every { result } returns mockk {
                    every { hasErrorThrows(any()) } throws TestUserException()
                }
            }

            val thrown = catchThrowable { service.registerUser(registerRequest) }
            assertThat(thrown).isInstanceOf(TestUserException::class.java)
        }

        @Test
        fun `register successful`() {
            val userCaptor = slot<User>()
            val registerRequest = UserRegisterRequest("username", "password")

            every { uidGenerator.generateUid() } returns Uid("uid")
            every { keyGenerator.generateKey() } returns UserCredentialsKey("key")
            every { passwordEncoder.encode("password") } returns "encodedPassword"
            every { repository.countByUsername(Username("username")) } returns 0
            every { repository.save(capture(userCaptor)) } returnsArgument 0
            every { validatorFactory.createValidator(any()) } returns mockk {
                every { result } returns mockk {
                    every { hasErrorThrows(any()) } just Runs
                }
            }

            service.registerUser(registerRequest)
            assertThat(userCaptor.isCaptured).isTrue
            assertThat(userCaptor.captured.uid).isEqualTo(Uid("uid"))
            assertThat(userCaptor.captured.username).isEqualTo(Username("username"))
            assertThat(userCaptor.captured.password).isEqualTo("encodedPassword")
            assertThat(userCaptor.captured.credentialsKey?.keyValue).isEqualTo("key")
        }
    }

    @Nested
    inner class RemoveUserTest {

        @Test
        fun `request user is not registered in repository`() {
            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.removeUser("username") }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `request user is registered in repository`() {
            val user: User = mockk(relaxed = true)

            every { repository.findById(Username("username")) } returns Optional.of(user)

            service.removeUser("username")
            verify { repository.delete(user) }
        }
    }

    inner class TestUserException: RuntimeException()
}