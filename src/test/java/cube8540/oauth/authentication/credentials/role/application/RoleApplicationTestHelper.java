package cube8540.oauth.authentication.credentials.role.application;

import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.role.domain.Role;
import cube8540.oauth.authentication.credentials.role.domain.RoleRepository;
import cube8540.oauth.authentication.credentials.role.infra.RoleValidationPolicy;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.util.Optional;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RoleApplicationTestHelper {

    static final String RAW_AUTHORITY_CODE = "AUTH-ID";
    static final AuthorityCode AUTHORITY_CODE = new AuthorityCode(RAW_AUTHORITY_CODE);

    static final String DESCRIPTION = "DESCRIPTION";
    static final String NEW_DESCRIPTION = "NEW-DESCRIPTION";

    static MockRole mockRole() {
        return new MockRole();
    }

    static MockRoleRepository mockRoleRepository() {
        return new MockRoleRepository();
    }

    static MocKValidationRule<Role> mocKValidationRule() {
        return new MocKValidationRule<>();
    }

    static MockValidationPolicy mockValidationPolicy() {
        return new MockValidationPolicy();
    }

    static class MockRole {
        private Role role;

        private MockRole() {
            this.role = mock(Role.class);
        }

        MockRole configDefault() {
            when(role.getCode()).thenReturn(AUTHORITY_CODE);
            when(role.getDescription()).thenReturn(DESCRIPTION);
            configNotBasic();
            return this;
        }

        MockRole configBasic() {
            when(role.isBasic()).thenReturn(true);
            return this;
        }

        MockRole configNotBasic() {
            when(role.isBasic()).thenReturn(false);
            return this;
        }

        Role build() {
            return role;
        }
    }

    static class MockRoleRepository {
        private RoleRepository repository;

        private MockRoleRepository() {
            this.repository = mock(RoleRepository.class);
            doAnswer(returnsFirstArg()).when(repository).save(isA(Role.class));
        }

        MockRoleRepository count(long count) {
            when(repository.countByCode(AUTHORITY_CODE)).thenReturn(count);
            return this;
        }

        MockRoleRepository registerRole(Role scope) {
            when(repository.findById(AUTHORITY_CODE)).thenReturn(Optional.of(scope));
            when(repository.countByCode(AUTHORITY_CODE)).thenReturn(1L);
            return this;
        }

        MockRoleRepository emptyRole() {
            when(repository.findById(AUTHORITY_CODE)).thenReturn(Optional.empty());
            when(repository.countByCode(AUTHORITY_CODE)).thenReturn(0L);
            return this;
        }

        RoleRepository build() {
            return repository;
        }
    }

    static class MockValidationPolicy {
        private RoleValidationPolicy policy;

        private MockValidationPolicy() {
            this.policy = mock(RoleValidationPolicy.class);
        }

        MockValidationPolicy roleCodeRule(ValidationRule<Role> roleCodeRule) {
            when(policy.roleCodeRule()).thenReturn(roleCodeRule);
            return this;
        }

        RoleValidationPolicy build() {
            return policy;
        }
    }

    static class MocKValidationRule<T> {
        private ValidationRule<T> validationRule;

        @SuppressWarnings("unchecked")
        private MocKValidationRule() {
            this.validationRule = mock(ValidationRule.class);
        }

        MocKValidationRule<T> configValidationTrue() {
            when(validationRule.isValid(any())).thenReturn(true);
            return this;
        }

        MocKValidationRule<T> configValidationFalse() {
            when(validationRule.isValid(any())).thenReturn(false);
            return this;
        }

        MocKValidationRule<T> error(ValidationError error) {
            when(validationRule.error()).thenReturn(error);
            return this;
        }

        ValidationRule<T> build() {
            return validationRule;
        }
    }
}
