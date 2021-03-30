package cube8540.oauth.authentication.resource.domain

import cube8540.validator.core.ValidationError
import cube8540.validator.core.ValidationRule
import cube8540.validator.core.Validator
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.*
import java.net.URI

class SecuredResourceTest {

    @Nested
    inner class ValidationTest {
        private val resourceValidatorFactory: SecuredResourceValidatorFactory = mockk()
        private val resource = SecuredResource(SecuredResourceId("resourceId"), URI.create("http://localhost"), ResourceMethod.ALL)

        @Test
        fun `resource data is invalid`() {
            val rule = mockk<ValidationRule<SecuredResource>> {
                every { isValid(resource) } returns false
                every { error() } returns ValidationError("resourceId", "test")
            }
            every { resourceValidatorFactory.createValidator(resource) } returns Validator.of(resource).registerRule(rule)

            val thrown = catchThrowable { resource.validation(resourceValidatorFactory) }
            assertThat(thrown).isInstanceOf(ResourceInvalidException::class.java)
        }

        @Test
        fun `resource data is allowed`() {
            val rule = mockk<ValidationRule<SecuredResource>> {
                every { isValid(resource) } returns true
            }
            every { resourceValidatorFactory.createValidator(resource) } returns Validator.of(resource).registerRule(rule)

            assertThatCode { resource.validation(resourceValidatorFactory) }.doesNotThrowAnyException()
        }
    }

    @Nested
    inner class ChangeResourceInfoTest {
        private val resource = SecuredResource(SecuredResourceId("resourceId"), URI.create("http://localhost"), ResourceMethod.ALL)

        @Test
        fun `change resource info`() {
            resource.changeResourceInfo(URI.create("http://change-host"), ResourceMethod.POST)

            assertThat(resource.resource).isEqualTo(URI.create("http://change-host"))
            assertThat(resource.method).isEqualTo(ResourceMethod.POST)
        }
    }

    @Nested
    @TestMethodOrder(value = MethodOrderer.OrderAnnotation::class)
    inner class ChangeAuthorityTest {
        private val resource = SecuredResource(SecuredResourceId("resourceId"), URI.create("http://localhost"), ResourceMethod.ALL)

        @Test
        @Order(1)
        fun `add authority`() {
            resource.addAuthority("ADD_AUTHORITY")

            assertThat(resource.authorities).contains(AccessibleAuthority("ADD_AUTHORITY"))
        }

        @Test
        @Order(2)
        fun `remove authority`() {
            resource.removeAuthority("ADD_AUTHORITY")

            assertThat(resource.authorities).doesNotContain(AccessibleAuthority("ADD_AUTHORITY"))
        }
    }
}