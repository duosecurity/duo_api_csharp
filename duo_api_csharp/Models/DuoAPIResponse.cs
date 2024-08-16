/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */
 
using System.Net;

namespace duo_api_csharp.Models
{
    /// <summary>
    /// API Response Wrapper
    /// </summary>
    public class DuoAPIResponse
    {
        /// <summary>
        /// The status code of the response
        /// </summary>
        public HttpStatusCode StatusCode { get; set; }
        
        /// <summary>
        /// The response data from the server
        /// </summary>
        public string? ResponseData { get; set; }
        
        /// <summary>
        /// If your request was successful or not
        /// </summary>
        public bool RequestSuccess { get; set; }
    }
}