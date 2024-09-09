/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using System.Net;

namespace duo_api_csharp.Classes
{
    /// <summary>
    /// Base exception thrown by the class library
    /// </summary>
    /// <param name="message">Error message</param>
    /// <param name="inner">Any inner exception, if present</param>
    /// <param name="statusCode">The HTTP status code if present</param>
    /// <param name="requestSuccess">Request success result, if present</param>
    public class DuoException(string message, Exception? inner = null, HttpStatusCode? statusCode = null, bool? requestSuccess = null) : Exception(message, inner)
    {
        /// <summary>
        /// The status code of the response
        /// </summary>
        public HttpStatusCode? StatusCode { get; } = statusCode;
        
        /// <summary>
        /// If your request was successful or not
        /// </summary>
        public bool? RequestSuccess { get; } = requestSuccess;
    }
}