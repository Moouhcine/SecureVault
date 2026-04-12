package dz.univ_usto.oss.secure_vault.security

import java.security.SecureRandom

object PasswordGenerator {
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val DIGITS = "0123456789"
    private const val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"
    private val random = SecureRandom()

    fun generate(length: Int = 16): String {
        val required = listOf(
            UPPER[random.nextInt(UPPER.length)],
            LOWER[random.nextInt(LOWER.length)],
            DIGITS[random.nextInt(DIGITS.length)],
            SYMBOLS[random.nextInt(SYMBOLS.length)]
        )
        val pool = (UPPER + LOWER + DIGITS + SYMBOLS).toCharArray()
        val remaining = CharArray(length - required.size) { pool[random.nextInt(pool.size)] }
        val combined = (required + remaining.toList()).toMutableList()
        combined.shuffle(random)
        return combined.joinToString("")
    }
}

