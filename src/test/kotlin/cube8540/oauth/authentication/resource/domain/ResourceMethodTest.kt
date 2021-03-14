package cube8540.oauth.authentication.resource.domain

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ResourceMethodTest {

    @Test
    fun `make by post string`() {
        val postLowercase = "post"
        val postUppercase = "POST"

        assertThat(ResourceMethod.of(postLowercase)).isEqualTo(ResourceMethod.POST)
        assertThat(ResourceMethod.of(postUppercase)).isEqualTo(ResourceMethod.POST)
    }

    @Test
    fun `make by get string`() {
        val getLowercase = "get"
        val getUppercase = "GET"

        assertThat(ResourceMethod.of(getLowercase)).isEqualTo(ResourceMethod.GET)
        assertThat(ResourceMethod.of(getUppercase)).isEqualTo(ResourceMethod.GET)
    }

    @Test
    fun `make by put string`() {
        val putLowercase = "put"
        val putUppercase = "PUT"

        assertThat(ResourceMethod.of(putLowercase)).isEqualTo(ResourceMethod.PUT)
        assertThat(ResourceMethod.of(putUppercase)).isEqualTo(ResourceMethod.PUT)
    }

    @Test
    fun `make by delete string`() {
        val deleteLowercase = "delete"
        val deleteUppercase = "DELETE"

        assertThat(ResourceMethod.of(deleteLowercase)).isEqualTo(ResourceMethod.DELETE)
        assertThat(ResourceMethod.of(deleteUppercase)).isEqualTo(ResourceMethod.DELETE)
    }

    @Test
    fun `make by patch string`() {
        val patchLowercase = "patch"
        val patchUppercase = "PATCH"

        assertThat(ResourceMethod.of(patchLowercase)).isEqualTo(ResourceMethod.PATCH)
        assertThat(ResourceMethod.of(patchUppercase)).isEqualTo(ResourceMethod.PATCH)
    }

    @Test
    fun `make by asterisk`() {
        assertThat(ResourceMethod.of("*")).isEqualTo(ResourceMethod.ALL)
    }
}