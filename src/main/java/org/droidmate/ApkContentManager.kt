/*
 * ATUA is a test automation tool for mobile Apps, which focuses on testing methods updated in each software release.
 * Copyright (C) 2019 - 2021 University of Luxembourg
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

package org.droidmate

import com.google.common.base.Stopwatch
import org.droidmate.legacy.Resource
import org.droidmate.manifest.ManifestInstrumenter
import org.droidmate.misc.SysCmdExecutor
import org.slf4j.LoggerFactory

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

/**
 * Originally copied to a large extent from the aggregator project.
 *
 * @author Original code by Manuel Benz (https://github.com/mbenz89)
 */
class ApkContentManager @Throws(IOException::class)
constructor(private val originalApkPath: Path, private val apkContentDir: Path, stagingDir: Path) {

    private val apkTool = Resource("apktool.jar").extractTo(stagingDir)

    @Throws(IOException::class)
    fun extractApk(forceOverwriteApkContentDir: Boolean, resource: Boolean = true, source: Boolean = true) {
        // Do not extract again if app has not changed since last extraction
        if (!forceOverwriteApkContentDir && Files.exists(apkContentDir) &&
            Files.getLastModifiedTime(apkContentDir) >= Files.getLastModifiedTime(originalApkPath)
        ) {
            log.info(
                "Apk hasn't changed since last extraction. Omitting ApkTool invocation. Use 'forceOverwriteApkContentDir' to force an update!")
            return
        }

        log.info("Invoking apk tool to extract apks content")
        val stopWatch = Stopwatch.createStarted()
        // Added -r, otherwise some apps invoked:
        // brut.androlib.AndrolibException: brut.common.BrutException: could not exec
        val params = ArrayList<String>()
        params.add("-f")
        params.add("d")
        if (!resource) {
            params.add("-r")
        }
        if (!source) {
            params.add("-s")
        }
        params.add("-o")
        params.add(apkContentDir.toString())
        params.add(originalApkPath.toString())
        invokeApkTool(*params.toTypedArray())

        log.info("Apk tool finished after {}", stopWatch)
    }

    @Throws(IOException::class)
    fun extractApk(forceOverwriteApkContentDir: Boolean) {
        // Do not extract again if app has not changed since last extraction
        if (!forceOverwriteApkContentDir && Files.exists(apkContentDir) &&
            Files.getLastModifiedTime(apkContentDir) >= Files.getLastModifiedTime(originalApkPath)
        ) {
            log.info(
                "Apk hasn't changed since last extraction. Omitting ApkTool invocation. Use 'forceOverwriteApkContentDir' to force an update!")
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
    fun buildApk(outApk: Path) {
        log.info("Invoking apk tool to build apk from content dir")
        val stopWatch = Stopwatch.createStarted()
        invokeApkTool("b", apkContentDir.toString(), "-o", outApk.toString())
        log.info("Apk tool finished after {}", stopWatch)
    }

    fun buildApk(outApk: Path, useAppt2: Boolean) {
        log.info("Invoking apk tool to build apk from content dir")
        val stopWatch = Stopwatch.createStarted()
        if (useAppt2)
            invokeApkTool("--use-aapt2", "b", apkContentDir.toString(), "-o", outApk.toString())
        else
            invokeApkTool("b", apkContentDir.toString(), "-o", outApk.toString())
        log.info("Apk tool finished after {}", stopWatch)
    }

    private fun invokeApkTool(vararg params: String) {
        try {
            val sysCmdExecutor = SysCmdExecutor()
            val cmdDescription = "Command for invoking the apk tool"
            sysCmdExecutor.executeWithoutTimeout(cmdDescription, "java", "-jar", apkTool.toString(), *params)
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

    fun changeMinSdkVersion() {
        val mi = ManifestInstrumenter(apkContentDir.resolve("AndroidManifest.xml"))
        mi.changeMinSDKVersionAndWriteOut()
    }

    @Throws(IOException::class)
    fun deleteMANIFESTMF() {
        val manifestMF = apkContentDir.resolve("original").resolve("META-INF").resolve("MANIFEST.MF")

        if (Files.exists(manifestMF)) {
            Files.delete(manifestMF)
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(this::class.java)
    }
}
