package cube8540.oauth.authentication.resource.domain

enum class ResourceMethod {

    GET, POST, PUT, DELETE, PATCH, ALL;

    companion object {
        @JvmStatic
        fun of(value: String) = when(value.toLowerCase()) {
            "get" -> GET
            "post" -> POST
            "put" -> PUT
            "delete" -> DELETE
            "patch" -> PATCH
            else -> ALL
        }
    }
}