package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;

import java.util.List;

public interface BasicAuthorityService {

    List<AuthorityCode> getBasicAuthority();

}
