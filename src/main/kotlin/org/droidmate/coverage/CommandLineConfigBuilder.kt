package org.droidmate.coverage

import com.natpryce.konfig.CommandLineOption
import com.natpryce.konfig.Configuration
import com.natpryce.konfig.ConfigurationProperties
import com.natpryce.konfig.overriding
import com.natpryce.konfig.parseArgs
import org.droidmate.configuration.ConfigProperties
import java.io.File

object CommandLineConfigBuilder {
    fun build(args: Array<String>): Configuration = build(parseArgs(
        args,
        CommandLineOption(ConfigProperties.Core.configPath,
            description = "Path to a custom configuration file, which replaces the default configuration.", short = "config"),
        CommandLineOption(CommandLineConfig.apk,
            description = "Apk to be instrumented. If a directory is provided, take the first non-instrumented app",
            short = "apk",
            metavar = "Path"
        ),
        CommandLineOption(CommandLineConfig.onlyAppPackage,
            description = "Instrument only statements in the app package",
            short = "app",
            metavar = "Boolean"
        ),
        CommandLineOption(CommandLineConfig.printToLogcat,
            description = "Print logged statements to logcat. Note: When being used alongside onlyAppPackage=false this may result in a significant performance impact",
            short = "print",
            metavar = "Boolean"
        ),
        CommandLineOption(CommandLineConfig.outputDir,
            description = "Output directory for instrumented Apk",
            short = "out",
            metavar = "Path"
        )
    ).first)

    private fun build(cfgCommandLine: Configuration): Configuration {
        val defaultConfig = ConfigurationProperties.fromResource("coverageCommandLineConfig.properties")

        val customFile = when {
            cfgCommandLine.contains(ConfigProperties.Core.configPath) -> File(cfgCommandLine[ConfigProperties.Core.configPath].path)
            defaultConfig.contains(ConfigProperties.Core.configPath) -> File(defaultConfig[ConfigProperties.Core.configPath].path)
            else -> null
        }

        val config : Configuration =
            // command line
            cfgCommandLine overriding
                    // overrides custom config file
                    (if (customFile?.exists() == true)
                        ConfigurationProperties.fromFile(customFile)
                    else
                        cfgCommandLine) overriding
                    // overrides default config file
                    defaultConfig
        return config
    }
}