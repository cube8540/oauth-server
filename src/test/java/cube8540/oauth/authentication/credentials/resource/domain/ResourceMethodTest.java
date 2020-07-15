package cube8540.oauth.authentication.credentials.resource.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("리소스 메소드 테스트")
class ResourceMethodTest {

    @Test
    @DisplayName("인자로 'post'를 받을시 POST 메소드를 반환해야 한다.")
    void ifGivenPostStringThenReturnsPostMethod() {
        ResourceMethod postWithLowercase = ResourceMethod.of("post");
        ResourceMethod postWithUppercase = ResourceMethod.of("POST");
        ResourceMethod postWithLowercaseAndUppercase = ResourceMethod.of("PoSt");

        assertEquals(ResourceMethod.POST, postWithLowercase);
        assertEquals(ResourceMethod.POST, postWithUppercase);
        assertEquals(ResourceMethod.POST, postWithLowercaseAndUppercase);
    }

    @Test
    @DisplayName("인자로 'get'를 받을시 POST 메소드를 반환해야 한다.")
    void ifGivenGetStringThenReturnsGetMethod() {
        ResourceMethod getWithLowercase = ResourceMethod.of("get");
        ResourceMethod getWithUppercase = ResourceMethod.of("GET");
        ResourceMethod getWithLowercaseAndUppercase = ResourceMethod.of("GeT");

        assertEquals(ResourceMethod.GET, getWithLowercase);
        assertEquals(ResourceMethod.GET, getWithUppercase);
        assertEquals(ResourceMethod.GET, getWithLowercaseAndUppercase);
    }

    @Test
    @DisplayName("인자로 'put'를 받을시 PUT 메소드를 반환해야 한다.")
    void ifGivenPutStringThenReturnsPutMethod() {
        ResourceMethod putWithLowercase = ResourceMethod.of("put");
        ResourceMethod putWithUppercase = ResourceMethod.of("PUT");
        ResourceMethod putWithLowercaseAndUppercase = ResourceMethod.of("PuT");

        assertEquals(ResourceMethod.PUT, putWithLowercase);
        assertEquals(ResourceMethod.PUT, putWithUppercase);
        assertEquals(ResourceMethod.PUT, putWithLowercaseAndUppercase);
    }

    @Test
    @DisplayName("인자로 'delete'를 받을시 DELETE 메소드를 반환해야 한다.")
    void ifGivenDeleteStringThenReturnsDeleteMethod() {
        ResourceMethod getWithLowercase = ResourceMethod.of("delete");
        ResourceMethod getWithUppercase = ResourceMethod.of("DELETE");
        ResourceMethod getWithLowercaseAndUppercase = ResourceMethod.of("DeLeTe");

        assertEquals(ResourceMethod.DELETE, getWithLowercase);
        assertEquals(ResourceMethod.DELETE, getWithUppercase);
        assertEquals(ResourceMethod.DELETE, getWithLowercaseAndUppercase);
    }

    @Test
    @DisplayName("인자로 '*'를 받을시 ALL 메소드를 반환해야 한다.")
    void ifGivenAsteriskStringThenReturnsALLMethod() {
        ResourceMethod all = ResourceMethod.of("*");

        assertEquals(ResourceMethod.ALL, all);
    }

}