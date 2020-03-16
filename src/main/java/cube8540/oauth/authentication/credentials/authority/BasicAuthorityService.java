package cube8540.oauth.authentication.credentials.authority;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;

import java.util.List;

public interface BasicAuthorityService {

    List<AuthorityCode> getBasicAuthority();

}
