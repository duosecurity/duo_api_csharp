/*
 * Copyright (c) 2022 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 */

using System;
using System.Collections.Generic;

public class Program
{
    static int Main(string[] args)
    {
        if (args.Length < 3)
        {
            System.Console.WriteLine("Usage: <integration key> <secret key> <integration host>");
            return 1;
        }
        string ikey = args[0];
        string skey = args[1];
        string host = args[2];
        var client = new Duo.DuoApi(ikey, skey, host);
        var parameters = new Dictionary<string, string>();
        var r = client.JSONApiCall<Dictionary<string, object>>(
            "GET", "/admin/v1/info/authentication_attempts", parameters);
        var attempts = r["authentication_attempts"] as Dictionary<string, object>;
        foreach (KeyValuePair<string, object> info in attempts) {
            var s = String.Format("{0} authentication(s) ended with {1}.",
                                  info.Value,
                                  info.Key);
            System.Console.WriteLine(s);
        }

        // /admin/v1/users returns a JSON Array instead of an object.
        var users = client.JSONApiCall<System.Collections.ArrayList>(
            "GET", "/admin/v1/users", parameters);
        System.Console.WriteLine(String.Format("{0} users.", users.Count));
        foreach (Dictionary<string, object> user in users) {
            System.Console.WriteLine(
                "\t" + "Username: " + (user["username"] as string));
        }

        // paging call
        int? offset = 0;
        while (offset != null) {
            var pagedUsers = client.JSONPagingApiCall<System.Collections.ArrayList>("GET", "/admin/v1/users", parameters, (int)offset, 10, out var metadata);
            System.Console.WriteLine(String.Format("{0} users at offset {1}", pagedUsers.Count, offset));
            foreach (Dictionary<string, object> user in pagedUsers) {
                System.Console.WriteLine(
                    "\t" + "Username: " + (user["username"] as string));
            }
            if (metadata.next_offset.HasValue)
            {
                offset = metadata.next_offset.Value;
            }
            else
            {
                offset = null;
            }
        }

        return 0;
    }
}

