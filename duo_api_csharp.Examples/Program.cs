/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using duo_api_csharp;
using duo_api_csharp.Classes;

namespace Examples
{
    public class Program
    {
        private static async Task<int> Main(string[] args)
        {
            // Setup the connection
            if( args.Length < 3 )
            {
                Console.WriteLine("Usage: <integration key> <secret key> <integration host>");
                return 1;
            }
            
            var ikey = args[0];
            var skey = args[1];
            var host = args[2];
            var client = new DuoAPI(ikey, skey, host);
            
            // Request the first 100 users
            try
            {
                var userResult = await client.Admin_v1.Users.GetUsers();
                if( userResult.Response == null )
                {
                    Console.WriteLine("Unable to retrieve users from Duo: ");
                    Console.WriteLine($"Error: ({userResult.ErrorCode}) {userResult.ErrorMessage}");
                    if( !string.IsNullOrEmpty(userResult.ErrorMessageDetail) ) Console.WriteLine($"Detailed Error: {userResult.ErrorMessageDetail}");
                    return 1;
                }
                
                // List first 100 of the available users
                Console.WriteLine($"Retrieved {userResult.Response.Count()} Users");
                foreach( var user in userResult.Response )
                {
                    Console.WriteLine($"User retrieved: {user.Username} (ID: {user.UserID})");
                }
            }
            catch( DuoException Ex )
            {
                Console.WriteLine("Unable to retrieve users from Duo: ");
                Console.WriteLine($"Exception: {Ex.Message}, Status Code: {Ex.StatusCode}, Request Success: {Ex.RequestSuccess}");
                if( Ex.InnerException != null ) Console.WriteLine($"Inner Exception: {Ex.InnerException.Message}");
            }
            
            return 0;
        }
    }
}