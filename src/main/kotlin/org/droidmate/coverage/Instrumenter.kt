// DroidMate, an automated execution generator for Android apps.
// Copyright (C) 2012-2018. Saarland University
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Current Maintainers:
// Nataniel Borges Jr. <nataniel dot borges at cispa dot saarland>
// Jenny Hotzkow <jenny dot hotzkow at cispa dot saarland>
//
// Former Maintainers:
// Konrad Jamrozik <jamrozik at st dot cs dot uni-saarland dot de>
//
// web: www.droidmate.org

package org.droidmate.coverage

import com.natpryce.konfig.Misconfiguration
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.droidmate.ApkContentManager
import org.droidmate.coverage.CommandLineConfig.apk
import org.droidmate.coverage.CommandLineConfig.onlyAppPackage
import org.droidmate.coverage.CommandLineConfig.outputDir
import org.droidmate.coverage.CommandLineConfig.printToLogcat
import org.droidmate.device.android_sdk.Apk
import org.droidmate.device.android_sdk.IApk
import org.droidmate.helpClasses.Helper
import org.droidmate.instrumentation.Runtime
import org.droidmate.legacy.Resource
import org.droidmate.legacy.asEnvDir
import org.droidmate.legacy.deleteDirectoryRecursively
import org.droidmate.manifest.ManifestConstants
import org.droidmate.misc.DroidmateException
import org.droidmate.misc.EnvironmentConstants
import org.droidmate.misc.JarsignerWrapper
import org.droidmate.misc.SysCmdExecutor
import org.json.JSONArray
import org.json.JSONObject
import org.slf4j.LoggerFactory
import soot.Body
import soot.BodyTransformer
import soot.PackManager
import soot.PhaseOptions
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.Transform
import soot.jimple.InvokeStmt
import soot.jimple.Jimple
import soot.jimple.internal.JIdentityStmt
import soot.options.Options
import java.io.BufferedReader
import java.io.File
import java.io.FileFilter
import java.io.FileReader
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.util.UUID
import kotlin.collections.ArrayList
import kotlin.collections.HashMap
import kotlin.collections.HashSet
import kotlin.streams.asSequence

/**
 * Instrument statements in an apk.
 *
 * @author Original code by Manuel Benz (https://github.com/mbenz89)
 */
public class Instrumenter @JvmOverloads constructor(
    private val stagingDir: Path,
    private val onlyCoverAppPackageName: Boolean,
    print: Boolean = false
) {
    private val printToLogcat = if (print) 1 else 0

    companion object {
        private val log by lazy { LoggerFactory.getLogger(this::class.java) }
        var allpackageClasses = HashMap<Long, String>()
        val allClasses = HashMap<Long, String>()
        var allMethods = HashMap<Long, String>()
        var allStatements = HashMap<Long, String>()

        var widgetId_String = HashMap<String, String>()

        var packageName: String = ""
        var useAppt2: Boolean = false
        @JvmStatic
        fun main(args: Array<String>) {
            try {
                val cfg = CommandLineConfigBuilder.build(args)
                log.info("Configuration:")
                log.info("  APK: ${cfg[apk]}")
                log.info("  Only app package: ${cfg[onlyAppPackage]}")
                log.info("  Print to logcat: ${cfg[printToLogcat]}")
                log.info("  Output dir: ${cfg[outputDir]}")
                val apkPath = Paths.get(cfg[apk].path)
                val onlyAppPackage = cfg[onlyAppPackage]
                val printToLogcat = cfg[printToLogcat]
                useAppt2 = cfg[CommandLineConfig.useAppt2]
                packageName = cfg[CommandLineConfig.packageName]
                val apkFiles: List<Path> = if (Files.isDirectory(apkPath)) {
                    Files.list(apkPath)
                        .asSequence()
                        .filter { it.fileName.toString().endsWith(".apk") }
                        .filterNot { it.fileName.toString().endsWith("-instrumented.apk") }.toList()
                } else {
                    listOf(apkPath.toAbsolutePath())
                }
                assert(apkFiles.isNotEmpty())

                val dstDir = if (cfg[outputDir].path == "./") {
                    apkFiles.first().parent
                } else {
                    Paths.get(cfg[outputDir].path)
                }
                val apkFile = apkFiles.first()
                assert(Files.isRegularFile(apkFile))
                val stagingDir = Files.createTempDirectory("staging")
                val instrumentationResult = try {
                    val apk = Apk.fromFile(apkFile)
                    Instrumenter(stagingDir, onlyAppPackage, printToLogcat).instrument(apk, dstDir)
                } finally {
                    stagingDir.deleteDirectoryRecursively()
                }
                log.info(
                    "Compiled apk moved to: ${instrumentationResult.first}\n" +
                            "Instrumentation results written to: ${instrumentationResult.second}"
                )
            } catch (e: Misconfiguration) {
                CommandLineConfigBuilder.build(arrayOf("--help"))
            }
        }
    }

    private val sysCmdExecutor = SysCmdExecutor()

    private val jarsignerWrapper = JarsignerWrapper(
        sysCmdExecutor,
        EnvironmentConstants.jarsigner.toAbsolutePath(),
        Resource("debug.keystore").extractTo(stagingDir)
    )

    private val helperClasses = listOf(
        "MonitorTcpServer",
        "Runtime",
        "SerializationHelper",
        "ServerRunnable",
        "TcpServerBase\$1",
        "TcpServerBase\$MonitorServerRunnable",
        "TcpServerBase"
    )

    private val excludedPackages = listOf(
        "android.support.",
        "com.google.",
        "com.android.",
        "android.java.",
        "android.view.",
        "androidx."
    )

    private lateinit var helperSootClasses: List<SootClass>
    private lateinit var runtime: Runtime
    private lateinit var apkContentManager: ApkContentManager

    private var isAllModifiedMethods = false
    /**
     * <p>
     * Inlines apk at path {@code apkPath} and puts its inlined version in {@code outputDir}.
     *
     * </p><p>
     * For example, if {@code apkPath} is:
     *
     *   /abc/def/calc.apk
     *
     * and {@code outputDir} is:
     *
     *   /abc/def/out/
     *
     * then the output inlined apk will have path
     *
     *   /abc/def/out/calc-inlined.apk
     *
     * </p>
     *
     * @param apk Apk to be instrumented
     * @param outputDir Directory where the APK file will be stored
     * @return A pair of paths, where the first path is the APK path and the second path is a
     *         JSON file containing all instrumented statements
     */
    fun instrument(apk: IApk, outputDir: Path): Pair<Path, Path> {
        if (!Files.exists(outputDir))
            Files.createDirectories(outputDir)
        assert(Files.isDirectory(outputDir))

        val workDir = Files.createTempDirectory("coverage")

        try {
            allMethods.clear()
            allStatements.clear()

            val packageFile = Files.list(apk.path.parent).filter { it.fileName.toString().contains(apk.packageName) && it.fileName.toString().endsWith("-package.txt") }.findFirst().orElse(null)

            val apkToolDir = workDir.resolve("apkTool")
            Files.createDirectories(apkToolDir)
//            apkContentManager = NewApkContentManager(apk.path, apkToolDir, workDir)
//            apkContentManager.extractApkWithResource(true)
            val tmpOutApk = workDir.resolve(apk.fileName)

            val apkToolNoResourceDir = workDir.resolve("apkToolNoResource")
            Files.createDirectories(apkToolNoResourceDir)

            apkContentManager = ApkContentManager(apk.path, apkToolDir, workDir)
            // apkContentManager.installFramework(true)
            apkContentManager.extractApk(true)
//            // apkContentManager.deleteMANIFESTMF()
            // Add internet permission
            Helper.initializeManifestInfo(apk.path.toString())
//          apkContentManager.changeMinSdkVersion()
            // The apk will need internet permissions to make sure that the TCP communication works
            if (!Helper.hasPermission(ManifestConstants.PERMISSION_INET)) {
                // apkContentManager.addPermissionsToApp(ManifestConstants.PERMISSION_INET)
            } /*else {
                Files.copy(apk.path, tmpOutApk)
            }*/
            apkContentManager.buildApk(tmpOutApk, useAppt2)
            val sootDir = workDir.resolve("soot")

            configSoot(tmpOutApk, sootDir)


            val instrumentedApk = instrumentAndSign(apk, sootDir)

            val outputApk = outputDir.resolve(
                instrumentedApk.fileName.toString()
                    .replace(".apk", "-instrumented.apk")
            )

            val rebuiltInstrumentedApk = buildNewApk(tmpOutApk, instrumentedApk, apkToolDir, workDir!!)

            Files.move(rebuiltInstrumentedApk, outputApk, StandardCopyOption.REPLACE_EXISTING)
            val instrumentedStatements = writeInstrumentationList(apk, outputDir)

            return Pair(outputApk, instrumentedStatements)
        } finally {
            workDir.deleteDirectoryRecursively()
        }
    }

    private fun buildNewApk(orginalApkPath: Path, instrumentedApk: Path, apkToolDir: Path, workDir: Path): Path {
        val orginalApkDir = workDir.resolve("original")
        var originalApkManager = ApkContentManager(orginalApkPath, orginalApkDir, workDir)
        originalApkManager.extractApk(true, false)
        val originalApkDirFile = File(orginalApkDir.toUri())
        var originalDexFolders = originalApkDirFile.listFiles(FileFilter { it.isDirectory }).filter { it.path.contains("smali") }
        val helpDexFolder: Path =
            if (originalDexFolders.size == 1) {
                originalApkDirFile.toPath().resolve("smali_classes2")
            } else {
                val lastDexFolder = originalDexFolders.sorted().last()
                val baseName = "smali_classes"
                val dexNumber = lastDexFolder.toPath().fileName.toString().substring(baseName.length).toInt()
                originalApkDirFile.toPath().resolve("$baseName${dexNumber + 1}")
            }

        val instrumentedApkDir = workDir.resolve("instrumented")
        var instrumentedApkManager = ApkContentManager(instrumentedApk, instrumentedApkDir, workDir)
        instrumentedApkManager.extractApk(true, false)
        val instrumentedApkDirFile = File(instrumentedApkDir.toUri())
        val instrumentedDexFolders = instrumentedApkDirFile.listFiles(FileFilter { it.isDirectory }).filter { it.path.contains("smali") }

        val helperSootClassSignatures = helperSootClasses.map { it.name }
        transformedClasses.filterNot { helperSootClassSignatures.contains(it) }.forEach { c ->
            // for each class, we find its path in the instrumented apk
            // and place it in the original apk
            val classPathString: String = creatPathFromClass(c)
            var classPath: Path? = null
            for (df in instrumentedDexFolders) {
                val tmpPath = Paths.get(df.toURI()).resolve(classPathString)
                if (Files.exists(tmpPath)) {
                    classPath = tmpPath
                    break
                }
            }
            if (classPath != null) {
                var copied = false
                for (df in originalDexFolders) {
                    val tmpPath = Paths.get(df.toURI()).resolve(classPathString)
                    if (Files.exists(tmpPath)) {
                        Files.copy(classPath, tmpPath, StandardCopyOption.REPLACE_EXISTING)
                        copied = true
                        log.debug("Replacing succesfully $c")
                        break
                    }
                }
                if (!copied) {
                    log.debug("Cannot find $c ")
                }
            } else {
                log.debug("Transformed class: $c not found")
            }
        }
        helperSootClassSignatures.forEach { c ->
            // for each class, we find its path in the instrumented apk
            // and place it in the original apk

            val classPathString: String = creatPathFromClass(c)
            var classPath: Path? = null
            for (df in instrumentedDexFolders) {
                val tmpPath = Paths.get(df.toURI()).resolve(classPathString)
                if (Files.exists(tmpPath)) {
                    classPath = tmpPath
                    break
                }
            }
            if (classPath != null) {
                val tmpPath = helpDexFolder.resolve(classPathString)
                Files.createDirectories(tmpPath.parent)
                Files.copy(classPath, tmpPath)
                log.debug("Copying succesfully $c")
            } else {
                log.debug("Transformed class: $c not found")
            }
        }
        originalApkManager.buildApk(instrumentedApk, useAppt2)
        log.info("Signing APK")
        val signedApk = jarsignerWrapper.signWithDebugKey(instrumentedApk)
        log.info("Signed APK at: $signedApk")
        return signedApk
    }

    private fun creatPathFromClass(c: String): String {
        val splitStrings = c.split(".")
        var stringPath = ""
        splitStrings.take(splitStrings.size - 1).forEach { s ->
            stringPath = stringPath + "/$s"
        }
        stringPath = stringPath + "/${splitStrings.last()}.smali"
        stringPath = stringPath.removeRange(0, 1)
        return stringPath
    }

    /**
     * Note: Whenever you change the files in Runtime.PACKAGE, recompile them and replace the existing .class'es
     * in the resources folder.
     */
    @Throws(IOException::class)
    private fun configSoot(processingApk: Path, sootOutputDir: Path) {
        Options.v().set_allow_phantom_refs(true)
        Options.v().set_src_prec(Options.src_prec_apk)
        Options.v().set_output_dir(sootOutputDir.toString())
        Options.v().set_debug(true)
        Options.v().set_validate(true)
        Options.v().set_output_format(Options.output_format_dex)
//        Options.v().set_include_all(true)
//        Options.v().set_whole_program(true)
        PhaseOptions.v().setPhaseOption("jb.tt", "enabled:false")
        PhaseOptions.v().setPhaseOption("jb.uce", "enabled:false")
        PhaseOptions.v().setPhaseOption("jj.uce", "enabled:false")
        PhaseOptions.v().setPhaseOption("jb.dtr", "enabled:false")
//         Options.v().set_app(true)
        val processDirs = ArrayList<String>()
        processDirs.add(processingApk.toString())

        val resourceDir = stagingDir
            .resolve("Runtime")

        val helperDir = resourceDir
            .resolve(Runtime.PACKAGE.replace('.', '/'))

        helperClasses
            // .filter { !it.contains("\$") }
            .forEach { Resource("$it.class").extractTo(helperDir) }

        Resource("libPackages.txt").extractTo(stagingDir)
        libraryPackageFile = stagingDir.resolve("libPackages.txt").toString()
        processLibraryPkgFile()
        Options.v().set_exclude(getLibraryPackage())
        if (packageName.isNotBlank()) {
            Options.v().set_exclude(getLibraryPackage())
            Options.v().set_include(arrayListOf(packageName + ".*"))
        }
        processDirs.add(resourceDir.toString())

        // Consider using multiplex, but it crashed for some apps
        Options.v().set_process_multiple_dex(true)
        Options.v().set_process_dir(processDirs)
        Options.v().set_android_jars("ANDROID_HOME".asEnvDir.resolve("platforms").toString())
        Options.v().set_force_overwrite(true)
        Options.v().set_android_api_version(28)
        Scene.v().loadNecessaryClasses()

//        log.info("Excluded libraries count: ${Options.v().exclude().size} ${Options.v().exclude()[0]}")
//        log.info("Library classes count: ${Scene.v().libraryClasses.size}")
//        log.info("Application classes count: ${Scene.v().applicationClasses.size}")
//        val debugGSM = "com.google.android.gms.internal.firebase-perf.zzz"
//        log.info("$debugGSM is application class: ${Scene.v().getSootClass(debugGSM).isApplicationClass}")

        runtime = Runtime.v(
            Paths.get(
                EnvironmentConstants.AVD_dir_for_temp_files,
                EnvironmentConstants.coverage_port_file_name
            )
        )
        helperSootClasses = helperClasses
            .map { Scene.v().getSootClass("${Runtime.PACKAGE}.$it") }
    }

    private fun IApk.instrumentWithSoot(sootDir: Path): Path {
        log.info("Start instrumenting coverage...")

        val transformer = ITransformer(this, onlyCoverAppPackageName)

        if (PackManager.v().getPack("jtp").get("jtp.androcov") == null) {
            PackManager.v().getPack("jtp").add(transformer)
        }

        PackManager.v().runPacks()
        PackManager.v().writeOutput()

        val instrumentedApk = sootDir.resolve(this.fileName)
        log.info("Instrumentation finished: $instrumentedApk")

        if (!Files.exists(instrumentedApk))
            throw DroidmateException("Failed to instrument $this. Instrumented APK not found.")

        return instrumentedApk
    }

    private fun instrumentAndSign(apk: IApk, sootOutputDir: Path): Path {
        val instrumentedApk = apk.instrumentWithSoot(sootOutputDir)

        log.info("Signing APK")
        val signedApk = jarsignerWrapper.signWithDebugKey(instrumentedApk)
        log.info("Signed APK at: $signedApk")
        return signedApk
    }

    val transformedClasses = HashSet<String>()
    /**
     * Custom statement instrumentation transformer.
     * Each statement is uniquely assigned by an incrementing long counter (2^64 universe).
     */
    inner class ITransformer(apk: IApk, onlyCoverAppPackageName: Boolean) :
        Transform("jtp.androcov", object : BodyTransformer() {

            private var counter: Long = 0
            private var methodCounter: Long = 0
            private var classCounter: Long = 0
            private val refinedPackageName = refinePackageName(apk)
            private var statementCounter: Long = 0
            private val mutex = Mutex()
            override fun internalTransform(b: Body, phaseName: String, options: MutableMap<String, String>) {
                val units = b.units
                runBlocking {
                    mutex.withLock {
                        val methodSig = b.method.signature

                        // Debug
/*                        if (b.method.declaringClass.name.contains("firebase-perf.zzz")) {
                            val iterator = units.snapshotIterator()
                            while (iterator.hasNext()) {
                                val u = iterator.next()
                                // Instrument statements
                                if (u !is JIdentityStmt) {
                                    if (u is DefinitionStmt) {
                                        log.info(u?.toString() + " (DefinitionStmt) : " + (u as DefinitionStmt).leftOp.type.toString() + " = " + (u as DefinitionStmt).rightOp.type.toString() + "(" + (u as DefinitionStmt).rightOp.javaClass +")")
                                        //  && (u as DefinitionStmt).leftOp.type.toString()
                                        //  + " : " + (u as DefinitionStmt).leftOp.type.toString()
                                    } else {
                                        log.info(u?.toString())
                                    }
                                }
                            }
                        }*/
                        // End Debug
                        // Important to use snapshotIterator here
                        // Skip if the current class is one of the classes we use to instrument the coverage
                        if (!helperSootClasses.any { b.method.declaringClass.name.contains(it.name) } &&
                            !excludedPackages.any { b.method.declaringClass.toString().startsWith(it) }) {
                            if (b.method.declaringClass.name.startsWith(refinedPackageName)) {
                                // instrumentOnCreateOnResume(b)
                                if (!allpackageClasses.containsValue(b.method.declaringClass.name)) {
                                    val classId = classCounter++
                                    allpackageClasses[classId] = b.method.declaringClass.name
                                    allClasses[classId] = b.method.declaringClass.name
                                }
                            }

                            if (!onlyCoverAppPackageName ||
                                (onlyCoverAppPackageName && b.method.declaringClass.name.startsWith(refinedPackageName))
                            ) {
                                // Perform instrumentation here

                                // log.info("Method $methodSig:")

                                var methodUuid: UUID? = null
                                if (methodUuid == null) {
                                    methodUuid = UUID.randomUUID()
                                }
                                val methodId = methodCounter
                                var methodInfo = "$methodSig uuid=$methodUuid"
                                allMethods.put(methodId, methodInfo)
                                val iterator = units.snapshotIterator()
                                while (iterator.hasNext()) {
                                    val u = iterator.next()
                                    // NGO change
                                    val uuid = UUID.randomUUID()
                                    // Instrument statements
                                    if (u !is JIdentityStmt) {
//                                        if (u is DefinitionStmt) {
//                                            log.info(u?.toString() + " (DefinitionStmt in $methodSig) : " + (u as DefinitionStmt).leftOp.type.toString() + " = " + (u as DefinitionStmt).rightOp.type.toString() )
//                                            //  && (u as DefinitionStmt).leftOp.type.toString()
//                                            //  + " : " + (u as DefinitionStmt).leftOp.type.toString()
//                                        }
//                                        // check the statement invoke findViewById function
//                                        else log.info(u?.toString())
                                        var viewId = ""
                                        val id = counter
                                        // instrumentFindViewById(u, b)
                                        allStatements[id] = "$u methodId=$methodUuid uuid=$uuid"

                                        val logStatement =
                                            runtime.makeCallToStatementPoint("$u methodId=$methodUuid uuid=$uuid", 0)
                                        // log.info("Insert statement point call: $logStatement")
                                        units.insertBefore(logStatement, u)
                                        counter++
                                    }
                                }
                                methodCounter++
                                if (!transformedClasses.contains(b.method.declaringClass.name)) {
                                    transformedClasses.add(b.method.declaringClass.name)
                                }
                            }
                            b.validate()
                        }
                    }
                }
            }
        })

//    private fun instrumentFindViewById(u: Unit?, b: Body) {
//        if (u is JInvokeStmt || u is JAssignStmt) {
//            val invokeExpr: VirtualInvokeExpr?
//            if (u is JInvokeStmt && u.invokeExpr is VirtualInvokeExpr) {
//                invokeExpr = u.invokeExpr as VirtualInvokeExpr
//            } else {
//                if (u is JAssignStmt) {
//                    val rightOpt = u.rightBox.value
//                    if (rightOpt is VirtualInvokeExpr) {
//                        invokeExpr = rightOpt
//                    } else {
//                        invokeExpr = null
//                    }
//                } else {
//                    invokeExpr = null
//                }
//            }
//
//            if (invokeExpr != null && invokeExpr.method.subSignature.equals(MethodNames.findViewByIdSubSig)) {
//                val newMethod: SootMethod?
//                if (GUIUserInteractionClient.allActivities.containsValue(invokeExpr.methodRef.declaringClass.name)) {
//                    newMethod = getMethod_FindViewByIdAlter(
//                        b.method.declaringClass,
//                        Scene.v().getSootClass("android.app.Activity"),
//                        invokeExpr.methodRef
//                    )
//
//                } else if (GUIUserInteractionClient.allDialogs.containsValue(invokeExpr.methodRef.declaringClass.name)) {
//                    newMethod = getMethod_FindViewByIdAlter(
//                        b.method.declaringClass,
//                        Scene.v().getSootClass("android.app.Dialog"),
//                        invokeExpr.methodRef
//                    )
//                } else {
//                    newMethod = getMethod_FindViewByIdAlter(
//                        b.method.declaringClass,
//                        Scene.v().getSootClass("android.view.View"),
//                        invokeExpr.methodRef
//                    )
//                }
//                if (newMethod != null) {
//                    val arguments = arrayListOf<Value>(invokeExpr.base, invokeExpr.args[0])
//                    val newVirtualInvokeExpr =
//                        Jimple.v().newVirtualInvokeExpr(b.thisLocal, newMethod.makeRef(), arguments)
//                    u.useBoxes.forEach {
//                        if (it is InvokeExprBox)
//                            it.value = newVirtualInvokeExpr
//                        else {
//                            if (it is ValueBox) {
//                                if (it.value is VirtualInvokeExpr) {
//                                    it.value = newVirtualInvokeExpr
//                                }
//                            }
//                        }
//                    }
//                    val resourceId = (invokeExpr.args[0] as IntConstant).value
//                    val logStatement = runtime.makeCallToAddCurrentWidgetPoint(
//                        resourceId,
//                        GUIUserInteractionClient.allWidgetIds[resourceId]?.idName ?: "",
//                        printToLogcat
//                    )
//                    b.units.insertBefore(logStatement, u)
//                }
//
//            }
//
//        }
//    }

    internal fun findSuperClass(derivedClass: SootClass, baseClass: SootClass): Boolean {
        var temp = derivedClass
        while (temp.hasSuperclass()) {
            if (temp.superclass == baseClass)
                return true
        }
        return false
    }

    private fun addMethodToClass(declaringClass: SootClass, method: SootMethod) {
        // create method
        declaringClass.addMethod(method)
        val body = Jimple.v().newBody(method)
        method.activeBody = body
        body.insertIdentityStmts()
        var invokeStmt: InvokeStmt? = null
        var superClass: SootClass = declaringClass.superclass
        while (superClass != null) {
            if (superClass.declaresMethod(method.subSignature)) {
                val parentMethodRef = superClass.getMethod(method.subSignature).makeRef()
                val specialInvokeExpr =
                    Jimple.v().newSpecialInvokeExpr(body.thisLocal, parentMethodRef, body.parameterLocals)
                invokeStmt = Jimple.v().newInvokeStmt(specialInvokeExpr)
                break
            }
            superClass = superClass.superclass
        }
        if (invokeStmt != null) {
            body.units.add(invokeStmt)
        }
        val currentActivityName = declaringClass.name
        val logStatement = runtime.makeCallToSetCurrentActivity(currentActivityName, printToLogcat)
        body.units.add(logStatement)
        body.units.add(Jimple.v().newReturnVoidStmt())
        body.validate()
    }


    /**
     * In the package has more than 2 parts, it returns the 2 first parts
     * @param apk Apk to extract the package name
     * @return The first to 2 segments of the package name
     */
    private fun refinePackageName(apk: IApk): String {
        if (packageName.isNotBlank())
            return packageName
        val parts = apk.packageName.split("\\.".toRegex())
            .dropLastWhile { it.isEmpty() }
            .toTypedArray()

        return if (parts.size > 2)
            "${parts[0]}.${parts[1]}"
        else
            apk.packageName
    }


    @Throws(IOException::class)
    private fun writeInstrumentationList(apk: IApk, outputDir: Path): Path {
        val outputMap = HashMap<String, Any>()
        outputMap["outputAPK"] = apk.fileName
        outputMap["allStatements"] = allStatements
        outputMap["allMethods"] = allMethods
        outputMap["allClassese"] = allClasses
        // outputMap["allPackageClasses"] = allpackageClasses
        val instrumentResultFile = outputDir.resolve("${apk.fileName}$INSTRUMENTATION_FILE_SUFFIX")
        val resultJson = JSONObject(outputMap)
        Files.write(instrumentResultFile, resultJson.toString(4).toByteArray())
        return instrumentResultFile
    }

    var libraryPackageFile = ""
    var libraryPackages: MutableList<String>? = null

    fun processLibraryPkgFile() {
        if (libraryPackageFile.isEmpty()) {
            return
        }
        try {
            val fr = FileReader(libraryPackageFile)
            val br = BufferedReader(fr)
            var curLine: String
            curLine = br.readLine()
            while (curLine != null) {
                if (!curLine.isEmpty()) {
                    addLibraryPackage(curLine)
                }
                curLine = br.readLine()
            }
            br.close()
            fr.close()
        } catch (e: Exception) {
        }
    }

    fun getLibraryPackage(): ArrayList<String> {
        val libraryPackageSoot = ArrayList<String>(libraryPackages)
//        libraryPackages?.forEach {
//            if (it.endsWith(".*")) {
//                val pkgName = it.substring(0, it.indexOf(".*"))
//                libraryPackageSoot.add(pkgName)
//            }
//        }

        return libraryPackageSoot
    }

    fun addLibraryPackage(packageName: String) {
        if (libraryPackages == null) {
            libraryPackages = ArrayList<String>()
        }
        libraryPackages!!.add(packageName)
    }

    fun isLibraryClass(className: String): Boolean {
        if (libraryPackages == null) return false
        for (pkg in libraryPackages!!) {
            if (pkg == className || (pkg.endsWith(".*") || pkg.endsWith("$*")) && className.startsWith(
                    pkg.substring(
                        0,
                        pkg.length - 1
                    )
                )
            ) {
                return true
            }
        }
        return false
    }
}