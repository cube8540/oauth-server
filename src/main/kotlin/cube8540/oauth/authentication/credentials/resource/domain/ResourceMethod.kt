package cube8540.oauth.authentication.credentials.resource.domain

enum class ResourceMethod {

    GET, POST, PUT, DELETE, ALL;

    companion object {
        @JvmStatic
        fun of(value: String) = when(value.toLowerCase()) {
            "get" -> GET
            "post" -> POST
            "put" -> PUT
            "delete" -> DELETE
            else -> ALL
        }
    }
}