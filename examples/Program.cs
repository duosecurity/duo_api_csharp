/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using duo_api_csharp;
using duo_api_csharp.SignatureTypes;

namespace Examples
{
    public class Program
    {
        static int Main(string[] args)
        {
            if( args.Length < 3 )
            {
                Console.WriteLine("Usage: <integration key> <secret key> <integration host>");
                return 1;
            }
            
            var ikey = args[0];
            var skey = args[1];
            var host = args[2];
            var client = new DuoAPI(ikey, skey, host);
            
            // V4 Signature request
            var r = client.APICall(
                HttpMethod.Get,
                "/admin/v1/info/authentication_attempts");
                
            Console.WriteLine($"Request state: {r.RequestSuccess}");
            Console.WriteLine($"Request code: {r.StatusCode}");
            Console.WriteLine($"Request data: {r.ResponseData}");
            
            // V5 Signature request
            var r1 = client.APICall(
                HttpMethod.Get,
                "/admin/v2/integrations",
                null,
                null,
                DuoSignatureTypes.Duo_SignatureTypeV5);
                
            Console.WriteLine($"Request state: {r1.RequestSuccess}");
            Console.WriteLine($"Request code: {r1.StatusCode}");
            Console.WriteLine($"Request data: {r1.ResponseData}");
            
            return 0;
        }
    }
}