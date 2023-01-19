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

/**
 * Created by Fabrizio P.
 *
 */
object JavaSignatureFormatter {

    internal var PAR_SEPARATOR = ","

    class SignatureFormatterResult(
        internal val className: String,
        internal var methodName: String,
        internal var arguments: String,
        internal var returnValue: String
    )

    fun translateJavaLowLevelSignatureToSoot(signature: String): String {
        val res = processJavaLowLevelSignature(signature)

        return extractSootSignature(res)
    }

    private fun extractSootSignature(res: SignatureFormatterResult): String {
        // <com.teleca.jamendo.api.impl.JamendoGet2ApiImpl: com.teleca.jamendo.api.Album[] getAlbumsByTracksId(int[])>

        var sig = "<"

        sig += res.className

        sig += ": "

        sig += res.returnValue

        sig += " "

        sig += res.methodName

        sig += "("
        sig += res.arguments
        sig += ")>"

        return sig
    }

    private fun processJavaLowLevelSignature(sig: String): SignatureFormatterResult {

        val pos = sig.indexOf("(")
        val methodName = sig.substring(0, pos)

        val argS = sig.indexOf("(")
        val argE = sig.indexOf(")")
        val arguments = sig.substring(argS + 1, argE)

        val retVal = sig.substring(argE + 1)

        val mArgs = processArrayName(arguments)
        val mRet = processArrayName(retVal)

        val cPos = methodName.lastIndexOf('.')

        val mCLass = methodName.substring(0, cPos)
        val mName = methodName.substring(cPos + 1)

        return SignatureFormatterResult(mCLass, mName, mArgs, mRet)
    }

    private fun processArrayName(argumentName: String): String {

        var sig = ""

        var i = 0
        val len = argumentName.length
        var post = ""
        var p = 0
        while (i < len) {

            if (p > 0) {
                sig += PAR_SEPARATOR
                p=0
            }

            val c = argumentName[i]
            if (c == 'L') {
                val end = argumentName.indexOf(';', i)
                val objType = argumentName.substring(i + 1, end)
                sig += objType.replace('/', '.')
                sig += post
                i = end
                post = ""
                p++
            } else if (c == '[') {
                post = "[]"
            } else {
                sig += translate(c)
                sig += post
                post = ""
                p++
            }
            i++
        }
        return sig
    }

    fun translate(c: Char): String {
        when (c) {
            'I' -> return "int"
            'B' -> return "byte"
            'D' -> return "double"
            'S' -> return "short"
            'J' -> return "long"
            'F' -> return "float"
            'C' -> return "char"
            'Z' -> return "boolean"
            'V' -> return "void"
        }
        throw IllegalArgumentException("Unknown ByteCode Type")
    }

    //  /**
    //   * return a class name that follows the java type definition
    //   * if the given class is an array, even multidimensional
    //   */
    //  public static String getNormalizedClassName(Class c) {
    //    if ( c.isArray() )
    //      return processArrayName(c);
    //    else
    //      return c.getName();
    //  }

    //  private static String estractArguments(Class[] arguments) {
    //    String args = "";
    //    for ( int i = 0; i < arguments.length; i++)
    //      args = args + getNormalizedClassName(arguments[i]) + ",";
    //    if ( !args.equals("") )
    //      args = args.substring(0, args.length() - 1);
    //    return args;
    //  }
    //
    //  public static String estractMethodSignature(String targetClass,String methodName, Class returnType , Class[] arguments) {
    //    String args = estractArguments(arguments);
    //    return //getNormalizedClassName(returnType) + " " +
    //      targetClass+"."+methodName + "(" + args + ")";
    //  }
    //
    //  public static String estractConstructorSignature(String constuctorName, Class[] arguments) {
    //    String args = estractArguments(arguments);
    //    return constuctorName + ".new(" + args + ")";
    //  }

    fun getClassName(methodSignarure: String): String {
        return ""
    }
}
