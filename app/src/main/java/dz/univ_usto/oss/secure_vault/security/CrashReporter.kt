package dz.univ_usto.oss.secure_vault.security

import android.content.Context
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

object CrashReporter {
    private const val FILE_NAME = "crash_report.txt"

    fun init(context: Context) {
        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                writeReport(context, throwable)
            } catch (_: Exception) {
            }
            defaultHandler?.uncaughtException(thread, throwable)
        }
    }

    fun loadReport(context: Context): String? {
        val file = File(context.filesDir, FILE_NAME)
        return if (file.exists()) file.readText() else null
    }

    fun clearReport(context: Context) {
        val file = File(context.filesDir, FILE_NAME)
        if (file.exists()) {
            file.delete()
        }
    }

    private fun writeReport(context: Context, throwable: Throwable) {
        val writer = StringWriter()
        throwable.printStackTrace(PrintWriter(writer))
        val report = writer.toString()
        File(context.filesDir, FILE_NAME).writeText(report)
    }
}

