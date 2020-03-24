package org.droidmate.coverage

import com.google.common.base.Stopwatch
import org.droidmate.legacy.Resource
import org.droidmate.manifest.ManifestInstrumenter
import org.droidmate.misc.SysCmdExecutor
import org.slf4j.LoggerFactory
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

public class NewApkContentManager @Throws(IOException::class)
constructor(private val originalApkPath: Path, private val apkContentDir: Path, stagingDir: Path) {

    private val apkTool = Resource("apktool.jar").extractTo(stagingDir)

    @Throws(IOException::class)
    fun extractApk(forceOverwriteApkContentDir: Boolean) {
        // Do not extract again if app has not changed since last extraction
        if (!forceOverwriteApkContentDir && Files.exists(apkContentDir) &&
            Files.getLastModifiedTime(apkContentDir) >= Files.getLastModifiedTime(originalApkPath)
        ) {
            log.info(
                "Apk hasn't changed since last extraction. Omitting ApkTool invocation. Use 'forceOverwriteApkContentDir' to force an update!"
            )
            return
        }

        log.info("Invoking apk tool to extract apks content")
        val stopWatch = Stopwatch.createStarted()
        // Added -r, otherwise some apps invoked:
        // brut.androlib.AndrolibException: brut.common.BrutException: could not exec
        invokeApkTool("-s", "-r", "-f", "d", "-o", apkContentDir.toString(), originalApkPath.toString())
        log.info("Apk tool finished after {}", stopWatch)
    }

    @Throws(IOException::class)
    fun installFramework(forceOverwriteApkContentDir: Boolean) {
        if (!forceOverwriteApkContentDir && Files.exists(apkContentDir) &&
            Files.getLastModifiedTime(apkContentDir) >= Files.getLastModifiedTime(originalApkPath)
        ) {
            log.info(
                "Apk hasn't changed since last extraction. Omitting ApkTool invocation. Use 'forceOverwriteApkContentDir' to force an update!"
            )
            return
        }

        log.info("Invoking apk tool to extract apks content")
        val stopWatch = Stopwatch.createStarted()
        // Added -r, otherwise some apps invoked:
        // brut.androlib.AndrolibException: brut.common.BrutException: could not exec
        invokeApkTool("if", "-o", apkContentDir.toString(), originalApkPath.toString())
        log.info("Apk tool finished after {}", stopWatch)
    }

    @Throws(IOException::class)
    fun extractApkWithResource(forceOverwriteApkContentDir: Boolean) {
        // Do not extract again if app has not changed since last extraction
        if (!forceOverwriteApkContentDir && Files.exists(apkContentDir) &&
            Files.getLastModifiedTime(apkContentDir) >= Files.getLastModifiedTime(originalApkPath)
        ) {
            log.info(
                "Apk hasn't changed since last extraction. Omitting ApkTool invocation. Use 'forceOverwriteApkContentDir' to force an update!"
            )
            return
        }

        log.info("Invoking apk tool to extract apks content")
        val stopWatch = Stopwatch.createStarted()
        // Added -r, otherwise some apps invoked:
        // brut.androlib.AndrolibException: brut.common.BrutException: could not exec
        invokeApkTool("-s", "-f", "d", "-o", apkContentDir.toString(), originalApkPath.toString())
        log.info("Apk tool finished after {}", stopWatch)
    }

    @Throws(IOException::class)
    fun deleteMANIFESTMF() {
        val manifestMF = apkContentDir.resolve("original").resolve("META-INF").resolve("MANIFEST.MF")

        if (Files.exists(manifestMF))

            Files.delete(manifestMF)
    }

    @Throws(IOException::class)
    fun buildApk(outApk: Path) {
        log.info("Invoking apk tool to build apk from content dir")
        val stopWatch = Stopwatch.createStarted()
        invokeApkTool("b", apkContentDir.toString(), "-c", "-o", outApk.toString())
        log.info("Apk tool finished after {}", stopWatch)
    }

    private fun invokeApkTool(vararg params: String) {
        try {
            val sysCmdExecutor = SysCmdExecutor()
            val cmdDescription = "Command for invoking the apk tool"
            sysCmdExecutor.execute(cmdDescription, "java", "-jar", apkTool.toString(), *params)
        } catch (e: Exception) {
            log.error("Error during ApkTool execution", e)
            throw RuntimeException(e)
        }
    }

    fun addPermissionsToApp(vararg permissions: String) {
        val mi = ManifestInstrumenter(apkContentDir.resolve("AndroidManifest.xml"))
        for (permission in permissions) {
            mi.addPermission(permission)
        }

        mi.writeOut()
    }

    companion object {
        private val log = LoggerFactory.getLogger(this::class.java)
    }
}