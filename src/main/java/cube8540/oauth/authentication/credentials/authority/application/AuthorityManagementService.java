package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;

import java.util.Collection;

public interface AuthorityManagementService {

    Long countAuthority(String code);

    AuthorityDetails getAuthority(String code);

    Collection<AuthorityDetails> getAuthorities();

    AuthorityDetails registerAuthority(AuthorityRegisterRequest registerRequest);

    AuthorityDetails modifyAuthority(String code, AuthorityModifyRequest modifyRequest);

    AuthorityDetails removeAuthority(String code);

}
