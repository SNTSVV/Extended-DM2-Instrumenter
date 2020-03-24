@rem
@rem Copyright 2015 the original author or authors.
@rem
@rem Licensed under the Apache License, Version 2.0 (the "License");
@rem you may not use this file except in compliance with the License.
@rem You may obtain a copy of the License at
@rem
@rem      http://www.apache.org/licenses/LICENSE-2.0
@rem
@rem Unless required by applicable law or agreed to in writing, software
@rem distributed under the License is distributed on an "AS IS" BASIS,
@rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@rem See the License for the specific language governing permissions and
@rem limitations under the License.
@rem

@if "%DEBUG%" == "" @echo off
@rem ##########################################################################
@rem
@rem  coverage startup script for Windows
@rem
@rem ##########################################################################

@rem Set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" setlocal

set DIRNAME=%~dp0
if "%DIRNAME%" == "" set DIRNAME=.
set APP_BASE_NAME=%~n0
set APP_HOME=%DIRNAME%..

@rem Add default JVM options here. You can also use JAVA_OPTS and COVERAGE_OPTS to pass JVM options to this script.
set DEFAULT_JVM_OPTS=

@rem Find java.exe
if defined JAVA_HOME goto findJavaFromJavaHome

set JAVA_EXE=java.exe
%JAVA_EXE% -version >NUL 2>&1
if "%ERRORLEVEL%" == "0" goto init

echo.
echo ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
echo.
echo Please set the JAVA_HOME variable in your environment to match the
echo location of your Java installation.

goto fail

:findJavaFromJavaHome
set JAVA_HOME=%JAVA_HOME:"=%
set JAVA_EXE=%JAVA_HOME%/bin/java.exe

if exist "%JAVA_EXE%" goto init

echo.
echo ERROR: JAVA_HOME is set to an invalid directory: %JAVA_HOME%
echo.
echo Please set the JAVA_HOME variable in your environment to match the
echo location of your Java installation.

goto fail

:init
@rem Get command-line arguments, handling Windows variants

if not "%OS%" == "Windows_NT" goto win9xME_args

:win9xME_args
@rem Slurp the command line arguments.
set CMD_LINE_ARGS=
set _SKIP=2

:win9xME_args_slurp
if "x%~1" == "x" goto execute

set CMD_LINE_ARGS=%*

:execute
@rem Setup the command line

set CLASSPATH=%APP_HOME%\lib\coverage-1.3.5-RC0.jar;%APP_HOME%\lib\droidmate-common-1.4.1-SNAPSHOT.jar;%APP_HOME%\lib\kotlin-stdlib-jdk8-1.3.21.jar;%APP_HOME%\lib\kotlinx-coroutines-core-1.1.1.jar;%APP_HOME%\lib\json-20160212.jar;%APP_HOME%\lib\soot-3.3.0.jar;%APP_HOME%\lib\soot-infoflow-android-2.7.1.jar;%APP_HOME%\lib\soot-infoflow-2.7.1.jar;%APP_HOME%\lib\heros-1.1.0.jar;%APP_HOME%\lib\jimfs-1.1.jar;%APP_HOME%\lib\dexlib2-2.2.5.jar;%APP_HOME%\lib\heros-1.0.1-SNAPSHOT.jar;%APP_HOME%\lib\guava-26.0-jre.jar;%APP_HOME%\lib\vtd-xml-2.13.4.jar;%APP_HOME%\lib\commons-lang3-3.8.jar;%APP_HOME%\lib\konfig-1.6.6.0.jar;%APP_HOME%\lib\kotlin-stdlib-jdk7-1.3.21.jar;%APP_HOME%\lib\platformInterfaceLib-master-SNAPSHOT.jar;%APP_HOME%\lib\kotlin-reflect-1.3.41.jar;%APP_HOME%\lib\kotlin-stdlib-1.3.41.jar;%APP_HOME%\lib\kotlinx-coroutines-core-common-1.1.1.jar;%APP_HOME%\lib\commons-io-2.6.jar;%APP_HOME%\lib\commons-exec-1.3.jar;%APP_HOME%\lib\logback-classic-1.2.3.jar;%APP_HOME%\lib\logback-core-1.2.3.jar;%APP_HOME%\lib\jsr305-3.0.2.jar;%APP_HOME%\lib\checker-qual-2.5.2.jar;%APP_HOME%\lib\error_prone_annotations-2.1.3.jar;%APP_HOME%\lib\j2objc-annotations-1.1.jar;%APP_HOME%\lib\animal-sniffer-annotations-1.14.jar;%APP_HOME%\lib\asm-debug-all-5.2.jar;%APP_HOME%\lib\xmlpull-1.1.3.4d_b4_min.jar;%APP_HOME%\lib\axml-2.0.0.jar;%APP_HOME%\lib\polyglot-2006.jar;%APP_HOME%\lib\jasmin-3.0.1.jar;%APP_HOME%\lib\slf4j-api-1.7.25.jar;%APP_HOME%\lib\functionaljava-4.2.jar;%APP_HOME%\lib\axml-2.0.0-SNAPSHOT.jar;%APP_HOME%\lib\axmlprinter-2016-07-27.jar;%APP_HOME%\lib\protobuf-java-2.5.0.jar;%APP_HOME%\lib\kotlin-stdlib-common-1.3.41.jar;%APP_HOME%\lib\annotations-13.0.jar;%APP_HOME%\lib\java_cup-0.9.2.jar;%APP_HOME%\lib\trove4j-3.0.3.jar

@rem Execute coverage
"%JAVA_EXE%" %DEFAULT_JVM_OPTS% %JAVA_OPTS% %COVERAGE_OPTS%  -classpath "%CLASSPATH%" org.droidmate.coverage.Instrumenter %CMD_LINE_ARGS%

:end
@rem End local scope for the variables with windows NT shell
if "%ERRORLEVEL%"=="0" goto mainEnd

:fail
rem Set variable COVERAGE_EXIT_CONSOLE if you need the _script_ return code instead of
rem the _cmd.exe /c_ return code!
if  not "" == "%COVERAGE_EXIT_CONSOLE%" exit 1
exit /b 1

:mainEnd
if "%OS%"=="Windows_NT" endlocal

:omega
