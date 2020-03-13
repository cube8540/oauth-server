package cube8540.oauth.authentication.credentials.authority.domain;

import cube8540.oauth.authentication.credentials.authority.domain.exception.ResourceInvalidException;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static cube8540.oauth.authentication.credentials.authority.domain.AuthorityTestHelper.mockResourceValidationPolicy;
import static cube8540.oauth.authentication.credentials.authority.domain.AuthorityTestHelper.mockResourceValidationRule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("보호 자원 테스트")
class SecuredResourceTest {

    private static final String RAW_RESOURCE_ID = "RESOURCE-ID";
    private static final SecuredResourceId RESOURCE_ID = new SecuredResourceId(RAW_RESOURCE_ID);

    private static final String RAW_RESOURCE = "/uri/**";
    private static final URI RESOURCE = URI.create(RAW_RESOURCE);
    private static final String RAW_CHANGE_RESOURCE = "/change/**";
    private static final URI CHANGE_RESOURCE = URI.create(RAW_CHANGE_RESOURCE);

    private static final ResourceMethod RESOURCE_METHOD = ResourceMethod.ALL;
    private static final ResourceMethod CHANGE_RESOURCE_METHOD = ResourceMethod.POST;

    private static final String RESOURCE_PROPERTY = "property";
    private static final String ERROR_MESSAGE = "message";

    @Nested
    @DisplayName("자원 정보 변경")
    class ChangeResourceInfo {
        private SecuredResource securedResource;

        @BeforeEach
        void setup() {
            this.securedResource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
        }

        @Test
        @DisplayName("변경된 정보를 저장해야 한다.")
        void shouldSaveChangedInfo() {
            securedResource.changeResourceInfo(CHANGE_RESOURCE, CHANGE_RESOURCE_METHOD);

            assertEquals(CHANGE_RESOURCE, securedResource.getResource());
            assertEquals(CHANGE_RESOURCE_METHOD, securedResource.getMethod());
        }
    }

    @Nested
    @DisplayName("유효성 검사")
    class Validation {

        @Nested
        @DisplayName("허용되지 않는 리소스 아이디 일시")
        class WhenNotAllowedResourceId {
            private SecuredResourceValidationPolicy validationPolicy;
            private ValidationError errorMessage;

            private SecuredResource resource;

            @BeforeEach
            void setup() {
                this.resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
                this.errorMessage = new ValidationError(RESOURCE_PROPERTY, ERROR_MESSAGE);

                ValidationRule<SecuredResource> idRule = mockResourceValidationRule().configReturnFalse(this.resource).validationError(errorMessage).build();
                ValidationRule<SecuredResource> resourceRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> methodRule = mockResourceValidationRule().configReturnTrue(this.resource).build();

                this.validationPolicy = mockResourceValidationPolicy().resourceIdRule(idRule).resourceRule(resourceRule).methodRule(methodRule).build();
            }

            @Test
            @DisplayName("ResourceInvalidException 이 발생해야 하며 예외 클래스에 에러 메시지가 포함되어야 한다.")
            void shouldThrowsResourceInvalidExceptionAndContainsErrorMessage() {
                ResourceInvalidException exception = assertThrows(ResourceInvalidException.class, () -> resource.validation(validationPolicy));
                assertTrue(exception.getErrors().contains(errorMessage));
            }
        }

        @Nested
        @DisplayName("허용되지 않는 리소스 일시")
        class WhenNotAllowedResource {
            private SecuredResourceValidationPolicy validationPolicy;
            private ValidationError errorMessage;

            private SecuredResource resource;

            @BeforeEach
            void setup() {
                this.resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
                this.errorMessage = new ValidationError(RESOURCE_PROPERTY, ERROR_MESSAGE);

                ValidationRule<SecuredResource> idRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> resourceRule = mockResourceValidationRule().configReturnFalse(this.resource).validationError(errorMessage).build();
                ValidationRule<SecuredResource> methodRule = mockResourceValidationRule().configReturnTrue(this.resource).build();

                this.validationPolicy = mockResourceValidationPolicy().resourceIdRule(idRule).resourceRule(resourceRule).methodRule(methodRule).build();
            }

            @Test
            @DisplayName("ResourceInvalidException 이 발생해야 하며 예외 클래스에 에러 메시지가 포함되어야 한다.")
            void shouldThrowsResourceInvalidExceptionAndContainsErrorMessage() {
                ResourceInvalidException exception = assertThrows(ResourceInvalidException.class, () -> resource.validation(validationPolicy));
                assertTrue(exception.getErrors().contains(errorMessage));
            }
        }

        @Nested
        @DisplayName("허용되지 않는 메소드 일시")
        class WhenNotAllowedMethod {
            private SecuredResourceValidationPolicy validationPolicy;
            private ValidationError errorMessage;

            private SecuredResource resource;

            @BeforeEach
            void setup() {
                this.resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
                this.errorMessage = new ValidationError(RESOURCE_PROPERTY, ERROR_MESSAGE);

                ValidationRule<SecuredResource> idRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> resourceRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> methodRule = mockResourceValidationRule().configReturnFalse(this.resource).validationError(errorMessage).build();

                this.validationPolicy = mockResourceValidationPolicy().resourceIdRule(idRule).resourceRule(resourceRule).methodRule(methodRule).build();
            }

            @Test
            @DisplayName("ResourceInvalidException 이 발생해야 하며 예외 클래스에 에러 메시지가 포함되어야 한다.")
            void shouldThrowsResourceInvalidExceptionAndContainsErrorMessage() {
                ResourceInvalidException exception = assertThrows(ResourceInvalidException.class, () -> resource.validation(validationPolicy));
                assertTrue(exception.getErrors().contains(errorMessage));
            }
        }
    }

}