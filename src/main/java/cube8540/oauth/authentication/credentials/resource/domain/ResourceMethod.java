package cube8540.oauth.authentication.credentials.resource.domain;

public enum ResourceMethod {

    GET, POST, PUT, DELETE, ALL;

    public static ResourceMethod of(String value) {
        switch (value.toLowerCase()) {
            case "get":
                return GET;
            case "post":
                return POST;
            case "put":
                return PUT;
            case "delete":
                return DELETE;
            default:
                return ALL;
        }
    }

}
