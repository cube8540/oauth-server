package cube8540.oauth.authentication.user.application

import cube8540.oauth.authentication.users.application.ChangePasswordRequest
import cube8540.oauth.authentication.users.application.DefaultUserPasswordService
import cube8540.oauth.authentication.users.application.ResetPasswordRequest
import cube8540.oauth.authentication.users.domain.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verifyOrder
import java.util.Optional
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.password.PasswordEncoder

class DefaultUserPasswordServiceTest {

    private val repository: UserRepository = mockk()
    private val passwordEncoder: PasswordEncoder = mockk()
    private val validatorFactory: UserValidatorFactory = mockk()
    private val keyGenerator: UserCredentialsKeyGenerator = mockk()

    private val service: DefaultUserPasswordService = DefaultUserPasswordService(repository, passwordEncoder)

    init {
        service.validatorFactory = validatorFactory
        service.keyGenerator = keyGenerator
        every { repository.save(any()) } returnsArgument 0
    }

    @Nested
    inner class ChangePasswordTest {

        @Test
        fun `request user is not registered in repository`() {
            val changePasswordRequest = ChangePasswordRequest("existingPassword", "newPassword")

            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.changePassword("username", changePasswordRequest) }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `request user is registered in repository`() {
            val changePasswordRequest = ChangePasswordRequest("existingPassword", "newPassword")
            val user: User = mockk(relaxed = true)

            every { repository.findById(Username("username")) } returns Optional.of(user)

            service.changePassword("username", changePasswordRequest)
            verifyOrder {
                user.changePassword("existingPassword", "newPassword", passwordEncoder)
                user.validation(validatorFactory)
                user.encrypted(passwordEncoder)
                repository.save(user)
            }
        }
    }

    @Nested
    inner class ForgotPasswordRequestTest {

        @Test
        fun `request user is not registered in repository`() {
            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.forgotPassword("username") }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `request user is registered in repository`() {
            val user: User = mockk(relaxed = true)

            every { repository.findById(Username("username")) } returns Optional.of(user)
            every { keyGenerator.generateKey() } returns UserCredentialsKey("key")

            service.forgotPassword("username")
            verifyOrder {
                user.forgotPassword(keyGenerator)
                repository.save(user)
            }
        }
    }

    @Nested
    inner class ValidationCredentialsKeyTest {

        @Test
        fun `request user is not registered in repository`() {
            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.validateCredentialsKey("username", "key") }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `password credentials key is expired`() {
            val user: User = mockk(relaxed = true) {
                every { passwordCredentialsKey } returns mockk {
                    every { matches("key") } returns UserKeyMatchedResult.EXPIRED
                }
            }
            every { repository.findById(Username("username")) } returns Optional.of(user)

            val result = service.validateCredentialsKey("username", "key")
            assertThat(result).isFalse
        }

        @Test
        fun `password credentials key is not matches`() {
            val user: User = mockk(relaxed = true) {
                every { passwordCredentialsKey } returns mockk {
                    every { matches("key") } returns UserKeyMatchedResult.NOT_MATCHED
                }
            }
            every { repository.findById(Username("username")) } returns Optional.of(user)

            val result = service.validateCredentialsKey("username", "key")
            assertThat(result).isFalse
        }

        @Test
        fun `password credentials key is not generated`() {
            val user: User = mockk(relaxed = true)

            every { repository.findById(Username("username")) } returns Optional.of(user)

            val result = service.validateCredentialsKey("username", "key")
            assertThat(result).isFalse
        }

        @Test
        fun `password credentials key is matches`() {
            val user: User = mockk(relaxed = true) {
                every { passwordCredentialsKey } returns mockk {
                    every { matches("key") } returns UserKeyMatchedResult.MATCHED
                }
            }
            every { repository.findById(Username("username")) } returns Optional.of(user)

            val result = service.validateCredentialsKey("username", "key")
            assertThat(result).isTrue
        }
    }

    @Nested
    inner class ResetPasswordTest {

        @Test
        fun `request user is not registered in repository`() {
            val resetPasswordRequest = ResetPasswordRequest("username", "key", "newPassword")

            every { repository.findById(Username("username")) } returns Optional.empty()

            val thrown = catchThrowable { service.resetPassword(resetPasswordRequest) }
            assertThat(thrown).isInstanceOf(UserNotFoundException::class.java)
        }

        @Test
        fun `request user is registered in repository`() {
            val resetPasswordRequest = ResetPasswordRequest("username", "key", "newPassword")
            val user: User = mockk(relaxed = true)

            every { repository.findById(Username("username")) } returns Optional.of(user)

            service.resetPassword(resetPasswordRequest)
            verifyOrder {
                user.resetPassword("key", "newPassword")
                user.validation(validatorFactory)
                user.encrypted(passwordEncoder)
                repository.save(user)
            }
        }
    }
}