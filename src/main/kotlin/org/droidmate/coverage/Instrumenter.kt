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

package org.droidmate.coverage

import com.google.common.collect.Lists
import com.natpryce.konfig.Misconfiguration
import kotlinx.coroutines.runBlocking
import org.droidmate.coverage.CommandLineConfig.apk
import org.droidmate.coverage.CommandLineConfig.outputDir
import org.droidmate.coverage.CommandLineConfig.onlyAppPackage
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
import org.json.JSONObject
import org.slf4j.LoggerFactory
import soot.jimple.internal.JIdentityStmt
import soot.options.Options
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import kotlin.streams.asSequence
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.droidmate.ApkContentManager
import org.droidmate.Hierarchy
import org.json.JSONArray
import soot.Body
import soot.BodyTransformer
import soot.G
import soot.IntType
import soot.Modifier
import soot.PackManager
import soot.PhaseOptions
import soot.RefType
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.SootMethodRef
import soot.Transform
import soot.Type
import soot.VoidType
import soot.dexpler.DexResolver
import soot.jimple.InvokeStmt
import soot.jimple.Jimple
import soot.jimple.internal.JReturnStmt
import soot.jimple.internal.JReturnVoidStmt
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.util.UUID
import kotlin.collections.ArrayList
import kotlin.collections.HashMap

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

        // key: source value: hashMapOf(widget, events)
        var modifiedMethods = ArrayList<String>()
        var widgetId_String = HashMap<String, String>()

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
            modifiedMethods.clear()

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
            // apkContentManager.deleteMANIFESTMF()
            // Add internet permission
            Helper.initializeManifestInfo(apk.path.toString())
//            apkContentManager.changeMinSdkVersion()
            // The apk will need internet permissions to make sure that the TCP communication works
            if (!Helper.hasPermission(ManifestConstants.PERMISSION_INET)) {
                apkContentManager.addPermissionsToApp(ManifestConstants.PERMISSION_INET)
                // apkContentManager.buildApk(tmpOutApk)
            } else {
                Files.copy(apk.path, tmpOutApk)
            }
            apkContentManager.buildApk(tmpOutApk)

//            Files.copy(apk.path, tmpOutApk)

//            Configs.project = tmpOutApk.toString()
//            Configs.manifestLocation = apkToolDir.resolve("AndroidManifest.xml").toAbsolutePath().toString()
//            Configs.resourceLocation = apkToolDir.resolve("res").toAbsolutePath().toString()

            val sootDir = workDir.resolve("soot")
//            configSoot(apk.path, sootDir)
            configSoot(tmpOutApk, sootDir)
            val diffFile = Files.list(apk.path.parent).filter { it.fileName.toString().contains(apk.packageName) && it.fileName.toString().endsWith("-diff.json") }.findFirst().orElse(null)
            readAppDiffFile(diffFile.toAbsolutePath().toString(), apk.packageName)
            val instrumentedApk = instrumentAndSign(apk, sootDir)
            val outputApk = outputDir.resolve(
                instrumentedApk.fileName.toString()
                    .replace(".apk", "-instrumented.apk")
            )

            Files.move(instrumentedApk, outputApk, StandardCopyOption.REPLACE_EXISTING)
            val instrumentedStatements = writeInstrumentationList(apk, outputDir)

            return Pair(outputApk, instrumentedStatements)
        } finally {
            workDir.deleteDirectoryRecursively()
        }
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
        Options.v().set_include_all(true)
        //Options.v().set_whole_program(true)
        PhaseOptions.v().setPhaseOption("jb.tt", "enabled:false")
        PhaseOptions.v().setPhaseOption("jb.uce", "enabled:false")
        PhaseOptions.v().setPhaseOption("jj.uce", "enabled:false")
        PhaseOptions.v().setPhaseOption("jb.dtr", "enabled:false")
        // Options.v().set_app(true)
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
        //Options.v().set_exclude(getLibraryPackage())
        processDirs.add(resourceDir.toString())

        // Consider using multiplex, but it crashed for some apps
        Options.v().set_process_multiple_dex(true)
        Options.v().set_process_dir(processDirs)
        Options.v().set_android_jars("ANDROID_HOME".asEnvDir.resolve("platforms").toString())
        Options.v().set_force_overwrite(true)
//      Options.v().set_android_api_version(27)
        Scene.v().loadNecessaryClasses()

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
                        // Important to use snapshotIterator here
                        // Skip if the current class is one of the classes we use to instrument the coverage
                        if (!helperSootClasses.any { b.method.declaringClass.name.contains(it.name) } &&
                            !excludedPackages.any { b.method.declaringClass.toString().startsWith(it) }) {
                            if (!isLibraryClass(b.method.declaringClass.name)) {
                                // instrumentOnCreateOnResume(b)
                                if (!allpackageClasses.containsValue(b.method.declaringClass.name)) {
                                    val classId = classCounter++
                                    allpackageClasses[classId] = b.method.declaringClass.name
                                    allClasses[classId] = b.method.declaringClass.name
                                }
                            }

                            val methodSig = b.method.signature

                            if (!onlyCoverAppPackageName ||
                                (onlyCoverAppPackageName && !isLibraryClass(b.method.declaringClass.name))
                            ) {
                                // Perform instrumentation here

                                //log.info("Method $methodSig:")

                                var methodUuid: UUID? = null
                                if (methodUuid == null) {
                                    methodUuid = UUID.randomUUID()
                                }
                                val methodId = methodCounter
                                var methodInfo = "$methodSig uuid=$methodUuid"
                                if (isModified(methodSig)) {
                                    methodInfo = "modified=true " + methodInfo
                                }
                                allMethods.put(methodId, methodInfo)
                                val iterator = units.snapshotIterator()
                                while (iterator.hasNext()) {
                                    val u = iterator.next()
                                    // NGO change
                                    val uuid = UUID.randomUUID()
                                    // Instrument statements
                                    if (u !is JIdentityStmt) {
                                        // check the statement invoke findViewById function
                                        // log.info(u?.toString())
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

    private fun instrumentOnCreateOnResume(b: Body) {
        val declaringClass = b.method.declaringClass
        val onResumeSubsig = "void onResume()"
        val onCreateSubsig = "void onCreate(android.os.Bundle)"
        val onRestartSubsig = "void onRestart()"
        if (!declaringClass.isAbstract && Hierarchy.v().isActivityClass(declaringClass) && !declaringClass.name.contains(
                "BaseActivity"
            )
        ) {
            if (!declaringClass.declaresMethod(onResumeSubsig)) {
                val onResume = SootMethod("onResume", emptyList(), VoidType.v())
                addMethodToClass(declaringClass, onResume)
            }
            if (!declaringClass.declaresMethod(onRestartSubsig)) {
                val onRestart = SootMethod("onRestart", emptyList(), VoidType.v())
                addMethodToClass(declaringClass, onRestart)
            }
            if (!declaringClass.declaresMethod(onCreateSubsig)) {
                val onCreate = SootMethod("onCreate", arrayListOf<Type>(RefType.v("android.os.Bundle")), VoidType.v())
                addMethodToClass(declaringClass, onCreate)
            }
            if (b.method.subSignature.equals(onCreateSubsig) || b.method.subSignature.equals(
                    onResumeSubsig
                ) || b.method.subSignature.equals(onRestartSubsig)
            ) {

                val currentActivityName = b.method.declaringClass.name
                val iterator = b.units.snapshotIterator()
                while (iterator.hasNext()) {
                    val u = iterator.next()
                    // find first not jidentitystatement
                    if (u !is JIdentityStmt) {
                        if (u is JReturnVoidStmt || u is JReturnStmt) {
                            val logStatement = runtime.makeCallToSetCurrentActivity(currentActivityName, printToLogcat)
                            b.units.insertBefore(logStatement, u)
                            break
                        }
                    }
                }
            }
        }
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

    private fun isModified(methodSig: String?): Boolean {
        if (modifiedMethods.contains(methodSig))
            return true
        return false
    }
//
//    private fun findCallingGUIElements(modMethod: SootMethod, callBack: SootMethod, refinedPackageName: String) {
//        //
//        /*if(allMethodInvocation.containsKey(modMethod.signature))
//        {
//            allMethodInvocation[modMethod.signature] = ArrayList<HashMap<String,String>>()
//        }*/
//        if (modMethod.equals(callBack)) //first call
//        {
//            if (modMethodInvocation.containsKey(modMethod.signature))
//                return
//
//            val eventHandlers = getEventHandlers(modMethod.signature)
//            if (eventHandlers.size > 0) {
//
//                addMethodInvocation(modMethod.signature, eventHandlers, modMethodInvocation)
//                addMethodInvocation(modMethod.signature, eventHandlers, cacheMethodInvocation)
//                return
//            }
//
//        }
//        // callback method is not a GUIElement but it can be processed before
//        if (!modMethod.equals(callBack) && cacheMethodInvocation.containsKey(callBack.signature)) {
//            // if it is, add callback's handlers
//            addMethodInvocation(modMethod.signature, cacheMethodInvocation[callBack.signature]!!, modMethodInvocation)
//            addMethodInvocation(modMethod.signature, cacheMethodInvocation[callBack.signature]!!, cacheMethodInvocation)
//            return
//        }
//        val eventHandlers = getEventHandlers(callBack.signature)
//        if (eventHandlers.size > 0) {
//            //if callback is an event handler, add event handlers related to callback
//            addMethodInvocation(modMethod.signature, eventHandlers, modMethodInvocation)
//            addMethodInvocation(modMethod.signature, eventHandlers, cacheMethodInvocation)
//            //add callback invocation to cache
//            addMethodInvocation(callBack.signature, eventHandlers, cacheMethodInvocation)
//            return
//        }
//        // if not, try to find its invoked callback
//        val callGraph = Scene.v().callGraph
//        //val sootMethod = Scene.v().getMethod(callBack.signature)
//        val sources = Sources(callGraph.edgesInto(callBack))
//        while (sources.hasNext()) {
//            val method = sources.next().method()
//            if (!method.equals(callBack) && method.signature.startsWith(refinedPackageName)) {
//                //log.info("findCallinfGUIElements for $method ")
//                findCallingGUIElements(modMethod, method, refinedPackageName)
//                //add eventhandlers of each method for current callback invocation
//                if (cacheMethodInvocation.contains(method.signature))
//                    addMethodInvocation(
//                        callBack.signature,
//                        cacheMethodInvocation[method.signature]!!,
//                        cacheMethodInvocation
//                    )
//            }
//        }
//    }

//    private fun addMethodInvocation(
//        method: String,
//        events: ArrayList<ActivityEvent>,
//        methodInvocations: HashMap<String, ArrayList<ActivityEvent>>
//    ) {
//        for (e in events) {
//            if (!methodInvocations.containsKey(method)) {
//                methodInvocations[method] = ArrayList<ActivityEvent>()
//            }
//            val eventExisted = methodInvocations[method]!!.contains(e)
//            if (!eventExisted)
//                methodInvocations[method]!!.add(e)
//        }
//    }

//    internal fun getEventHandlers(handler: String): ArrayList<ActivityEvent> {
//        if (!GUIUserInteractionClient.allEventHandlers.contains(handler))
//            return ArrayList()
//        var guiElements = ArrayList<ActivityEvent>() //each element compose "source", "widget", "eventType"
//        if (!GUIUserInteractionClient.allExplicitEventHandlers.contains(handler)) {
//            GUIUserInteractionClient.allCallbacks.filter {
//                it.second.contains(handler)
//            }.forEach {
//                val invokedEventHandler = it.first
//                guiElements.add(it.first)
//            }
//        }
//
//        val i = GUIUserInteractionClient.widgetEvents.iterator()
//        if (i != null) {
//            while (i.hasNext()) {
//                val element = i.next()
//                val widget = element.key
//                val eventHandlers = element.value
//                for (e in eventHandlers) {
//
//                    if (e.handler.first().signature == handler)
//                        guiElements.add(e)
//                }
//            }
//        }
//        return guiElements
//    }

    /**
     * In the package has more than 2 parts, it returns the 2 first parts
     * @param apk Apk to extract the package name
     * @return The first to 2 segments of the package name
     */
    private fun refinePackageName(apk: IApk): String {
        val parts = apk.packageName.split("\\.".toRegex())
            .dropLastWhile { it.isEmpty() }
            .toTypedArray()

        return if (parts.size > 2)
            "${parts[0]}.${parts[1]}"
        else
            apk.packageName
    }

//    internal fun readWidgetMap() =//This is an ondemand implementation of signature patch
//        try {
//            val fr = FileReader(Configs.sootAndroidDir + "/scripts/consts/widgetMap")
//            val br = BufferedReader(fr)
//            var curLine = br.readLine()
//            while (curLine != null) {
//                val curLineArr = curLine.split(",".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
//                if (curLineArr.size != 2) {
//                    Logger.verb("MAIN", "[MAP] Str: $curLine is not a valid map")
//                }
//                if (Configs.widgetMap.containsKey(curLineArr[0])) {
//                    Logger.verb("MAIN", "[MAP] Str: collision at key " + curLineArr[0])
//                } else {
//                    Configs.widgetMap[curLineArr[0]] = curLineArr[1]
//                }
//                curLine = br.readLine()
//            }
//            Logger.trace("MAIN", "[INFO] Widget map loaded")
//        } catch (e: IOException) {
//            e.printStackTrace()
//        }

//    private fun configSootAndroid() {
//        val sootandroidDir = Paths.get("./sootandroid")
//        // Configs.project = config[apk].path.toString()
//        Configs.benchmarkName = "I don't know"
//        Configs.sdkDir = "ANDROID_HOME".asEnvDir.toString()
//        Configs.apiLevel = "android-25"
//        Configs.android = "ANDROID_HOME".asEnvDir.resolve("platforms")
//            .resolve(Configs.apiLevel).resolve("android.jar").toString()
//        Configs.guiAnalysis = true
//        Configs.listenerSpecFile = sootandroidDir.resolve("listeners.xml").toAbsolutePath().toString()
//        Configs.wtgSpecFile = sootandroidDir.resolve("wtg.xml").toAbsolutePath().toString()
//        Configs.implicitIntent = false
//        Configs.resolveContext = false
//        Configs.trackWholeExec = false
//        Configs.clients.add(GUIUserInteractionClient::class.qualifiedName)
//        // Configs.clients.add(PathGenerationClient::class.qualifiedName)
//        // Configs.workerNum = //default = 16
//        // Configs.mockScene = //default = true
//        Configs.hardwareEvent = true
//        // Configs.detectLeak // default = false
//        // Configs.testGenStrategy // default = false
//        // Configs.sDepth  //default = 4
//        // Configs.allowLoop // default = false
//        // Configs.epDepth // default = 3
//        // Configs.clientParams.add("GUI")
//        // Configs.asyncStrategy // default
//        // Configs.genTestCase // default false
//        // Configs.pathoutfilename
//        // Configs.monitoredClass
//        Configs.libraryPackageFile =
//            sootandroidDir.resolve("libPackages.txt").toAbsolutePath().toString()// may try libPackages.txt
//
//        // Configs.fastMode = true //default
//        Configs.sootAndroidDir = sootandroidDir.toAbsolutePath().toString()
//
//        // Configs.flowgraphOutput = args[++i]
//        // Configs.enableStringAnalysis = true
//        // Configs.enableSetTextAnalysis = true
//        Configs.processing()
//
//    }

//    /**
//     * Computes the classpath to be used by soot.
//     */
//    internal fun computeClasspath(): String {
//        // Compute classpath
//        val classpathBuffer = StringBuffer(Configs.android + ":" + Configs.jre)
//        for (s in Configs.depJars) {
//            classpathBuffer.append(":$s")
//        }
//
//        // TODO(tony): add jar files of third-party libraries if necessary
//        for (s in Configs.extLibs) {
//            classpathBuffer.append(":$s/bin/classes")
//        }
//
//        return classpathBuffer.toString()
//    }

    /**
     *
     */
    internal fun readAppDiffFile(filename: String, refinedPackageName: String) {
        val appDiffFile = File(filename)
        if (!appDiffFile.exists()) {
            log.error("Cannot find app diff file: $filename")
            return
        }

        val appdiffJson = JSONObject(String(Files.readAllBytes(appDiffFile.toPath())))
        val modMethods = appdiffJson.get("methodsChanged") as JSONArray

        for (m in modMethods) {
            val sootSignature = JavaSignatureFormatter.translateJavaLowLevelSignatureToSoot(m.toString())
            if (!Scene.v().containsMethod(sootSignature))
                continue
            val declaredClass = Scene.v().getMethod(sootSignature).declaringClass
            if (isLibraryClass(declaredClass.name))
                continue

            modifiedMethods.add(sootSignature)
        }
    }

//    /**
//     *
//     */
//    internal fun produceViewInvocationHashMap(): HashMap<String, Any> {
//        val hashmapResult = HashMap<String, Any>()
//        for ((k, v) in modMethodInvocation) {
//
//            for (e in v) {
//                if (!hashmapResult.containsKey(e.window.toString())) {
//                    hashmapResult[e.window.toString()] = HashMap<String, Any>()
//                }
//                val window = hashmapResult[e.window.toString()] as HashMap<String, Any>
//                if (!window.contains(e.widget.toString())) {
//                    window[e.widget.toString()] = ArrayList<HashMap<String, Any>>()
//                }
//
//                val widget = window[e.widget.toString()] as ArrayList<HashMap<String, Any>>
//                var hasEvent = false
//                var eventIndex: Int? = null
//                for ((i, rE) in widget.withIndex()) {
//                    if (rE["eventType"] == e.eventType) {
//                        hasEvent = true
//                        eventIndex = i
//                        break
//                    }
//                }
//                if (hasEvent) {
//                    (widget[eventIndex!!]["modMethods"] as ArrayList<String>).add(k)
//                } else {
//                    widget.add(
//                        hashMapOf(
//                            "eventType" to e.eventType, "eventHandlers" to e.handler.map { it.signature },
//                            "modMethods" to arrayListOf<String>(k)
//                        )
//                    )
//
//                }
//
//            }
//
//        }
//        return hashmapResult
//    }

    fun getMethod_FindViewByIdAlter(
        activityClass: SootClass,
        callerClass: SootClass,
        findViewByIdMethodRef: SootMethodRef
    ): SootMethod? {
        // create new method and add to activityClass
        val androidViewType = RefType.v("android.view.View")
        // Create new method
        val method = SootMethod(
            "findViewByIdAlter",
            arrayListOf<Type>(RefType.v(callerClass), IntType.v()) as MutableList<Type>?,
            androidViewType,
            Modifier.PUBLIC
        )
        // check class has already this method
        if (Scene.v().containsMethod(SootMethod.getSignature(activityClass, method.subSignature)))
            return activityClass.getMethod(method.subSignature)

        activityClass.addMethod(method)
        // Create body
        val body = Jimple.v().newBody(method)
        method.activeBody = body
        // adding this-assigment
        // val thisLocal = Jimple.v().newThisRef(activityClass.type)
        body.insertIdentityStmts()

        // adding a local
        /*
        val arg = Jimple.v().newLocal("l0", IntType.v())
        body.locals.add(arg)
        body.units.add(Jimple.v().newIdentityStmt(arg,Jimple.v().newParameterRef(IntType.v(),0)))
        */

        val caller = body.getParameterLocal(0)
        val resourceId = body.getParameterLocal(1)

        // get findViewById method
        // invoke original findViewById
        val findViewByIdInvokeExpr = Jimple.v().newVirtualInvokeExpr(caller, findViewByIdMethodRef, resourceId)
        // body.units.add(Jimple.v().newInvokeStmt(findViewByIdInvokeExpr))
        // assign invoked result to an object
        val objResult = Jimple.v().newLocal("\$l1", androidViewType)
        body.locals.add(objResult)
        val assignStmt = Jimple.v().newAssignStmt(objResult, findViewByIdInvokeExpr)
        body.units.add(assignStmt)

        val returnStm = Jimple.v().newReturnStmt(objResult)
        body.units.add(returnStm)
        return method
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
        val libraryPackageSoot = ArrayList<String>()
        libraryPackages?.forEach {
            if (it.endsWith(".*")) {
                val pkgName = it.substring(0, it.indexOf(".*"))
                libraryPackageSoot.add(pkgName)
            }
        }
        return libraryPackageSoot
    }

    fun addLibraryPackage(packageName: String) {
        if (libraryPackages == null) {
            libraryPackages = Lists.newArrayList<String>()
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