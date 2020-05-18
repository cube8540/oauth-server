package cube8540.oauth.authentication.credentials.role.application;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.AuthorityDetailsService;

import java.util.List;

public interface RoleManagementService extends AuthorityDetailsService {

    Long countByRoleCode(String code);

    List<AuthorityDetails> loadAllAuthorities();

    AuthorityDetails registerNewRole(RoleRegisterRequest registerRequest);

    AuthorityDetails modifyRole(String code, RoleModifyRequest modifyRequest);

    AuthorityDetails removeRole(String code);

}
