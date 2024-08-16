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
    
    public class DuoAPIException : DuoException
    {
        public int Code { get; private set; }
        public string ApiMessage { get; private set; }
        public string ApiMessageDetail { get; private set; }

        public DuoAPIException(int code,
                            int http_status,
                            string api_message,
                            string api_message_detail)
            : base(FormatMessage(code, api_message, api_message_detail), null)
        {
            this.Code = code;
            this.ApiMessage = api_message;
            this.ApiMessageDetail = api_message_detail;
        }

        private static string FormatMessage(int code,
                                            string api_message,
                                            string api_message_detail)
        {
            return string.Format(
                "Duo API Error {0}: '{1}' ('{2}')", code, api_message, api_message_detail);
        }
    }
}