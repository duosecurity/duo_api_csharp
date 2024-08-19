/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

namespace duo_api_csharp.Models
{
    public interface DuoRequestData
    {
        public string ContentTypeHeader { get; }
    }
    
    public class DuoParamRequestData : DuoRequestData
    {
        public string ContentTypeHeader => "application/x-www-form-urlencoded";
        
        public Dictionary<string,string> RequestData { get; set; } = new();
    }
    
    public class DuoJsonRequestData : DuoRequestData
    {
        public string ContentTypeHeader => "application/json";
        
        public string RequestData { get; set; } = "";
    }
    
    public class DuoJsonRequestDataObject(object jsonObj) : DuoRequestData
    {
        public string ContentTypeHeader => "application/json";
        
        public object? RequestData { get; init; } = jsonObj;
    }
}