package cube8540.oauth.authentication.credentials.authority;

import java.util.List;

public interface AuthorityDetails {

    String getCode();

    String getDescription();

    boolean isBasic();

    List<String> getAccessibleResources();

}
