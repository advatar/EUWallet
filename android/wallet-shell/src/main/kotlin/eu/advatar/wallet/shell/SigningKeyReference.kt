package eu.advatar.wallet.shell

private val allowedKeyReference = Regex("[A-Za-z0-9._:-]{1,128}")

internal fun validatedSigningKeyReference(keyRef: String): String {
    require(allowedKeyReference.matches(keyRef)) {
        "keyRef must contain 1-128 ASCII letters, digits, '.', '_', ':', or '-'"
    }
    return keyRef
}

internal fun androidKeystoreAlias(keyRef: String): String =
    "eu.advatar.wallet.signing.${validatedSigningKeyReference(keyRef)}"
