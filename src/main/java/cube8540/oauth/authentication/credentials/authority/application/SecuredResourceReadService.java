package cube8540.oauth.authentication.credentials.authority.application;

import java.util.List;

public interface SecuredResourceReadService {

    Long count(String resourceId);

    List<SecuredResourceDetails> getResources();
}
