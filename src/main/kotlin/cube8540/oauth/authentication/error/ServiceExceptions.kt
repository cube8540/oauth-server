package cube8540.oauth.authentication.error

import cube8540.validator.core.ValidationError
import cube8540.validator.core.exception.ValidateException

open class ServiceException(val code: String, message: String): RuntimeException(message)

open class ServiceInvalidException(
    val code: String,
    errors: Array<ValidationError>
) : ValidateException(* errors) {

    constructor(code: String, errors: Collection<ValidationError>): this(code, errors.toTypedArray())

}