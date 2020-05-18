package cube8540.oauth.authentication.credentials.resource.domain;

import cube8540.oauth.authentication.credentials.resource.domain.exception.ResourceInvalidException;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.ACCESSIBLE_AUTHORITY;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.AUTHORITY_TYPE;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.CHANGE_RESOURCE;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.CHANGE_RESOURCE_METHOD;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.ERROR_MESSAGE;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.ERROR_PROPERTY;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.RAW_AUTHORITY_CODE;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.RESOURCE;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.RESOURCE_ID;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.RESOURCE_METHOD;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.mockResourceValidationPolicy;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.mockResourceValidationRule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("보호 자원 테스트")
class SecuredResourceTest {

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
    @DisplayName("접근 권한 추가")
    class AddAuthority {
        private SecuredResource securedResource;

        @BeforeEach
        void setup() {
            this.securedResource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
        }

        @Test
        @DisplayName("인자로 받은 접근 권한을 추가 해야 한다.")
        void shouldAddGivenAuthority() {
            this.securedResource.addAuthority(RAW_AUTHORITY_CODE, AUTHORITY_TYPE);

            assertTrue(securedResource.getAuthorities().contains(ACCESSIBLE_AUTHORITY));
        }
    }

    @Nested
    @DisplayName("접근 권한 삭제")
    class RemoveAuthority {
        private SecuredResource securedResource;

        @BeforeEach
        void setup() {
            this.securedResource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
            this.securedResource.addAuthority(RAW_AUTHORITY_CODE, AUTHORITY_TYPE);
        }

        @Test
        @DisplayName("인자로 받은 접근 권한을 삭제 해야 한다.")
        void shouldRemoveGivenAuthority() {
            this.securedResource.removeAuthority(RAW_AUTHORITY_CODE, AUTHORITY_TYPE);

            assertFalse(securedResource.getAuthorities().contains(ACCESSIBLE_AUTHORITY));
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
                this.errorMessage = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);

                ValidationRule<SecuredResource> idRule = mockResourceValidationRule().configReturnFalse(this.resource).validationError(errorMessage).build();
                ValidationRule<SecuredResource> resourceRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> methodRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> scopeAuthoritiesRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> roleAuthoritiesRule = mockResourceValidationRule().configReturnTrue(this.resource).build();

                this.validationPolicy = mockResourceValidationPolicy().resourceIdRule(idRule)
                        .resourceRule(resourceRule).methodRule(methodRule).scopeAuthoritiesRule(scopeAuthoritiesRule)
                        .roleAuthoritiesRule(roleAuthoritiesRule).build();
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
                this.errorMessage = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);

                ValidationRule<SecuredResource> idRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> resourceRule = mockResourceValidationRule().configReturnFalse(this.resource).validationError(errorMessage).build();
                ValidationRule<SecuredResource> methodRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> scopeRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> roleRule = mockResourceValidationRule().configReturnTrue(this.resource).build();

                this.validationPolicy = mockResourceValidationPolicy().resourceIdRule(idRule)
                        .resourceRule(resourceRule).methodRule(methodRule).scopeAuthoritiesRule(scopeRule).roleAuthoritiesRule(roleRule).build();
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
                this.errorMessage = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);

                ValidationRule<SecuredResource> idRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> resourceRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> methodRule = mockResourceValidationRule().configReturnFalse(this.resource).validationError(errorMessage).build();
                ValidationRule<SecuredResource> scopeRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> roleRule = mockResourceValidationRule().configReturnTrue(this.resource).build();

                this.validationPolicy = mockResourceValidationPolicy().resourceIdRule(idRule)
                        .resourceRule(resourceRule).methodRule(methodRule).scopeAuthoritiesRule(scopeRule).roleAuthoritiesRule(roleRule).build();
            }

            @Test
            @DisplayName("ResourceInvalidException 이 발생해야 하며 예외 클래스에 에러 메시지가 포함되어야 한다.")
            void shouldThrowsResourceInvalidExceptionAndContainsErrorMessage() {
                ResourceInvalidException exception = assertThrows(ResourceInvalidException.class, () -> resource.validation(validationPolicy));
                assertTrue(exception.getErrors().contains(errorMessage));
            }
        }

        @Nested
        @DisplayName("허용 되지 않는 접근 스코프 일시")
        class WhenNotAllowedScope {
            private SecuredResourceValidationPolicy validationPolicy;
            private ValidationError errorMessage;

            private SecuredResource resource;

            @BeforeEach
            void setup() {
                this.resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
                this.errorMessage = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);

                ValidationRule<SecuredResource> idRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> resourceRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> methodRule= mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> scopeRule = mockResourceValidationRule().configReturnFalse(this.resource).validationError(errorMessage).build();
                ValidationRule<SecuredResource> roleRule = mockResourceValidationRule().configReturnTrue(this.resource).build();

                this.validationPolicy = mockResourceValidationPolicy().resourceIdRule(idRule)
                        .resourceRule(resourceRule).methodRule(methodRule).scopeAuthoritiesRule(scopeRule).roleAuthoritiesRule(roleRule).build();
            }

            @Test
            @DisplayName("ResourceInvalidException 이 발생해야 하며 예외 클래스에 에러 메시지가 포함되어야 한다.")
            void shouldThrowsResourceInvalidExceptionAndContainsErrorMessage() {
                ResourceInvalidException exception = assertThrows(ResourceInvalidException.class, () -> resource.validation(validationPolicy));
                assertTrue(exception.getErrors().contains(errorMessage));
            }
        }

        @Nested
        @DisplayName("허용 되지 않는 접근 권한 일시")
        class WhenNotAllowedAuthorities {
            private SecuredResourceValidationPolicy validationPolicy;
            private ValidationError errorMessage;

            private SecuredResource resource;

            @BeforeEach
            void setup() {
                this.resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
                this.errorMessage = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);

                ValidationRule<SecuredResource> idRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> resourceRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> methodRule= mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> scopeRule = mockResourceValidationRule().configReturnTrue(this.resource).build();
                ValidationRule<SecuredResource> roleRule = mockResourceValidationRule().configReturnFalse(this.resource).validationError(errorMessage).build();

                this.validationPolicy = mockResourceValidationPolicy().resourceIdRule(idRule)
                        .resourceRule(resourceRule).methodRule(methodRule).scopeAuthoritiesRule(scopeRule).roleAuthoritiesRule(roleRule).build();
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