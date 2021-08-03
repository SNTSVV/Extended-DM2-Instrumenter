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
        ),
        CommandLineOption(CommandLineConfig.packageName,
        description = "Package name for instrumented Apk",
        short = "package",
        metavar = "String"
        ),
        CommandLineOption(CommandLineConfig.useAppt2,
            description = "Use appt2 for building Apk",
            short = "appt2",
            metavar = "Boolean"
        )
    ).first)

    private fun build(cfgCommandLine: Configuration): Configuration {
        val defaultConfig = ConfigurationProperties.fromResource("coverageCommandLineConfig.properties")

        val customFile = when {
            cfgCommandLine.contains(ConfigProperties.Core.configPath) -> File(cfgCommandLine[ConfigProperties.Core.configPath].path)
            defaultConfig.contains(ConfigProperties.Core.configPath) -> File(defaultConfig[ConfigProperties.Core.configPath].path)
            else -> null
        }

        val config: Configuration =
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