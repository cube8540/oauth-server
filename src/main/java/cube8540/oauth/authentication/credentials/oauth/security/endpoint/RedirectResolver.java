package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;

import java.net.URI;

public interface RedirectResolver {

    URI resolveRedirectURI(String redirectURI, OAuth2ClientDetails clientDetails);

}
