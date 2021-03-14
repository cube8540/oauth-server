package cube8540.oauth.authentication.resource.application

import cube8540.oauth.authentication.UnitTestValidationException
import cube8540.oauth.authentication.resource.domain.*
import io.mockk.*
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.URI
import java.util.*
import kotlin.random.Random

class DefaultSecuredResourceManagementServiceTest {

    private val repository: SecuredResourceRepository = mockk(relaxed = true)
    private val validatorFactory: SecuredResourceValidatorFactory = mockk()

    private val service: DefaultSecuredResourceManagementService = DefaultSecuredResourceManagementService(repository)

    init {
        every { repository.save(any()) } returnsArgument 0

        service.validatorFactory = validatorFactory
    }

    @Nested
    inner class CountingTest {

        @Test
        fun `resource counting`() {
            val count = Random.nextLong(0, 100)

            every { repository.countByResourceId(SecuredResourceId("resourceId")) } returns count

            val results = service.count("resourceId")
            assertThat(results).isEqualTo(count)
        }
    }

    @Nested
    inner class RegisterNewResourceTest {

        @Test
        fun `resource is already registered in repository`() {
            val accessibleAuthorities = listOf(AccessibleAuthorityValue("access.test.1"), AccessibleAuthorityValue("access.test.2"))
            val request = SecuredResourceRegisterRequest("resourceId", "http://localhost:8080", "POST", accessibleAuthorities)

            every { repository.countByResourceId(SecuredResourceId("resourceId")) } returns 1

            val thrown = catchThrowable { service.registerNewResource(request) }
            assertThat(thrown).isInstanceOf(ResourceRegisterException::class.java)
        }

        @Test
        fun `request resource data is invalid`() {
            val accessibleAuthorities = listOf(AccessibleAuthorityValue("access.test.1"), AccessibleAuthorityValue("access.test.2"))
            val request = SecuredResourceRegisterRequest("resourceId", "http://localhost:8080", "POST", accessibleAuthorities)

            every { repository.countByResourceId(SecuredResourceId("resourceId")) } returns 0
            every { validatorFactory.createValidator(any()) } returns mockk {
                every { result } returns mockk {
                    every { hasErrorThrows(any()) } throws UnitTestValidationException()
                }
            }

            val thrown = catchThrowable { service.registerNewResource(request) }
            assertThat(thrown).isInstanceOf(UnitTestValidationException::class.java)
        }

        @Test
        fun `register successful`() {
            val resourceCaptor = slot<SecuredResource>()
            val accessibleAuthorities = listOf(AccessibleAuthorityValue("access.test.1"), AccessibleAuthorityValue("access.test.2"))
            val request = SecuredResourceRegisterRequest("resourceId", "http://localhost:8080", "POST", accessibleAuthorities)

            every { repository.countByResourceId(SecuredResourceId("resourceId")) } returns 0
            every { repository.save(capture(resourceCaptor)) } returnsArgument 0
            every { validatorFactory.createValidator(any()) } returns mockk {
                every { result } returns mockk {
                    every { hasErrorThrows(any()) } just Runs
                }
            }

            service.registerNewResource(request)
            assertThat(resourceCaptor.isCaptured).isTrue
            assertThat(resourceCaptor.captured.resourceId).isEqualTo(SecuredResourceId("resourceId"))
            assertThat(resourceCaptor.captured.resource).isEqualTo(URI.create("http://localhost:8080"))
            assertThat(resourceCaptor.captured.method).isEqualTo(ResourceMethod.POST)
            assertThat(resourceCaptor.captured.authorities)
                .isEqualTo(setOf(AccessibleAuthority("access.test.1"), AccessibleAuthority("access.test.2")))
        }
    }

    @Nested
    inner class ModifyResourceTest {

        @Test
        fun `request resource is not registered in repository`() {
            val newAuthorities = listOf(AccessibleAuthorityValue("new.access.1"), AccessibleAuthorityValue("new.access.2"))
            val removeAuthorities = listOf(AccessibleAuthorityValue("rem.access.1"), AccessibleAuthorityValue("rem.access.2"))
            val request = SecuredResourceModifyRequest("http://modify:8080", "PUT", newAuthorities, removeAuthorities)

            every { repository.findById(SecuredResourceId("resourceId")) } returns Optional.empty()

            val thrown = catchThrowable { service.modifyResource("resourceId", request) }
            assertThat(thrown).isInstanceOf(ResourceNotFoundException::class.java)
        }

        @Test
        fun `request resource data is invalid`() {
            val storedResource: SecuredResource = mockk(relaxed = true)
            val newAuthorities = listOf(AccessibleAuthorityValue("new.access.1"), AccessibleAuthorityValue("new.access.2"))
            val removeAuthorities = listOf(AccessibleAuthorityValue("rem.access.1"), AccessibleAuthorityValue("rem.access.2"))
            val request = SecuredResourceModifyRequest("http://modify:8080", "PUT", newAuthorities, removeAuthorities)

            every { repository.findById(SecuredResourceId("resourceId")) } returns Optional.of(storedResource)
            every { storedResource.validation(validatorFactory) } throws UnitTestValidationException()

            val thrown = catchThrowable { service.modifyResource("resourceId", request) }
            assertThat(thrown).isInstanceOf(UnitTestValidationException::class.java)
            verifyOrder {
                storedResource.changeResourceInfo(URI.create("http://modify:8080"), ResourceMethod.PUT)
                storedResource.removeAuthority("rem.access.1")
                storedResource.removeAuthority("rem.access.2")
                storedResource.addAuthority("new.access.1")
                storedResource.addAuthority("new.access.2")
                storedResource.validation(validatorFactory)
            }
        }

        @Test
        fun `modify successful`() {
            val savedResourceCaptor = slot<SecuredResource>()
            val storedResource: SecuredResource = mockk(relaxed = true)
            val newAuthorities = listOf(AccessibleAuthorityValue("new.access.1"), AccessibleAuthorityValue("new.access.2"))
            val removeAuthorities = listOf(AccessibleAuthorityValue("rem.access.1"), AccessibleAuthorityValue("rem.access.2"))
            val request = SecuredResourceModifyRequest("http://modify:8080", "PUT", newAuthorities, removeAuthorities)

            every { repository.findById(SecuredResourceId("resourceId")) } returns Optional.of(storedResource)
            every { storedResource.validation(validatorFactory) } just Runs

            service.modifyResource("resourceId", request)
            verifyOrder {
                storedResource.changeResourceInfo(URI.create("http://modify:8080"), ResourceMethod.PUT)
                storedResource.removeAuthority("rem.access.1")
                storedResource.removeAuthority("rem.access.2")
                storedResource.addAuthority("new.access.1")
                storedResource.addAuthority("new.access.2")
                storedResource.validation(validatorFactory)
                repository.save(capture(savedResourceCaptor))
            }
            assertThat(savedResourceCaptor.captured).isEqualTo(storedResource)
        }
    }

    @Nested
    inner class RemoveResourceTest {

        @Test
        fun `request resource is not registered in repository`() {
            every { repository.findById(SecuredResourceId("resourceId")) } returns Optional.empty()

            val thrown = catchThrowable { service.removeResource("resourceId") }
            assertThat(thrown).isInstanceOf(ResourceNotFoundException::class.java)
        }

        @Test
        fun `request resource is registered in repository`() {
            val resource: SecuredResource = mockk(relaxed = true)

            every { repository.findById(SecuredResourceId("resourceId")) } returns Optional.of(resource)

            service.removeResource("resourceId")
            verify { repository.delete(resource) }
        }
    }
}