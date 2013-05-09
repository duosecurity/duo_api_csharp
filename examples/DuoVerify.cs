/*
 * Copyright (c) 2013 Duo Security
 * All rights reserved, all wrongs reversed.
 */

using Duo;
using System;
using System.Collections.Generic;

class DuoVerifyExample
{
    static int Main(string[] args)
    {
        if (args.Length < 4)
        {
            System.Console.WriteLine("Usage: <integration key> <secret key> <integration host> <E.164-formatted phone number>");
            return 1;
        }
        string ikey = args[0];
        string skey = args[1];
        string host = args[2];
        string phone = args[3];
        var client = new Duo.DuoApi(ikey, skey, host);
        var parameters = new Dictionary<string, string>();
        parameters["phone"] = phone;
        parameters["message"] = "The PIN is <pin>";

        // Start a call
        var r = client.JSONApiCall<Dictionary<string, object>>(
            "POST", "/verify/v1/call", parameters);

        // Get the transaction ID from the response.
        if (! r.ContainsKey("txid"))
        {
            System.Console.WriteLine("Could not send PIN!");
            return 1;
        }

        // Poll the txid for the status of the transaction.
        System.Console.WriteLine("The PIN is " + r["pin"]);
        parameters.Clear();
        parameters["txid"] = r["txid"] as String;
        String state;
        do
        {
            var status_res =
                client.JSONApiCall<Dictionary<string, object>>(
            "GET", "/verify/v1/status", parameters);
            state = status_res["state"] as String;
            System.Console.WriteLine(status_res["info"]);
        } while (state != "ended");

        return 0;
    }
}

