package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.AuthorityDetailsService;

public interface AuthorityManagementService extends AuthorityDetailsService {

    Long countAuthority(String code);

    AuthorityDetails registerAuthority(AuthorityRegisterRequest registerRequest);

    AuthorityDetails modifyAuthority(String code, AuthorityModifyRequest modifyRequest);

    AuthorityDetails removeAuthority(String code);

}
