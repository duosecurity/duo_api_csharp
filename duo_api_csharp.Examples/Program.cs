/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using duo_api_csharp;

namespace Examples
{
    public class Program
    {
        static async Task<int> Main(string[] args)
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
            
            
            return 0;
        }
    }
}