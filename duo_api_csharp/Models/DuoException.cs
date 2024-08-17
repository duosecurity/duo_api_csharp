/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */
 
namespace duo_api_csharp.Models
{
    /// <summary>
    /// Base exception thrown by the class library
    /// </summary>
    /// <param name="message">Error message</param>
    /// <param name="inner">Any inner exception, if present</param>
    public class DuoException(string message, Exception? inner = null) : Exception(message, inner);
}