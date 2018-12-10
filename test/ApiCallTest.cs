﻿using Duo;
using System;
using System.Net;
using System.Threading;
using System.Collections.Generic;
using System.IO;

using Microsoft.VisualStudio.TestTools.UnitTesting;

// Subclass DuoApi so we can test using HTTP rather than HTTPS
public class TestDuoApi : DuoApi
{
    public TestDuoApi(string ikey, string skey, string host)
        : base(ikey, skey, host, null, "http")
    {
    }
    public TestDuoApi(string ikey, string skey, string host, string user_agent)
        : base(ikey, skey, host, user_agent, "http")
    {
    }
}

public class TestServer
{
    public TestServer(string ikey, string skey)
    {
        this.ikey = ikey;
        this.skey = skey;
    }

    public delegate string TestDispatchHandler(HttpListenerContext ctx);
    public TestDispatchHandler handler {
        get
        {
            lock (this)
            {
                return this._handler;
            }
        }
        set {
            lock (this)
            {
                this._handler = value;
            }
        }
    }

    public void Run()
    {
        HttpListener listener = new HttpListener();
        listener.Prefixes.Add("http://localhost:8080/");
        listener.Start();

        // Wait for a request
        HttpListenerContext context = listener.GetContext();
        HttpListenerRequest request = context.Request;

        // process the request
        string path = request.Url.AbsolutePath;
        string responseString;

        try
        {
            responseString = handler(context);
        }
        catch (Exception e)
        {
            responseString = e.ToString();
        }

        // write the response
        HttpListenerResponse response = context.Response;
        System.IO.Stream output = response.OutputStream;

        if (!String.IsNullOrEmpty(responseString))
        {
            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            output.Write(buffer, 0, buffer.Length);
        }
        output.Close();

        // shut down the listener
        listener.Stop();
    }

    private string ikey;
    private string skey;
    private TestDispatchHandler _handler;
}


[TestClass]
public class TestApiCall
{
    private const string test_ikey = "DI9FD6NAKXN4B9DTCCB7";
    private const string test_skey = "RScfSuMrpL52TaciEhGtZkGjg8W4JSe5luPL63J8";
    private const string test_host = "localhost:8080";

    [TestInitialize]
    public void SetUp()
    {
        api = new TestDuoApi(test_ikey, test_skey, test_host);
        srv = new TestServer(test_ikey, test_skey);
        srvThread = new Thread(srv.Run);
        srvThread.Start();
    }

    [TestCleanup]
    public void CleanUp()
    {
        srvThread.Join();
    }

    [TestMethod]
    public void Test401Response()
    {
        srv.handler = delegate(HttpListenerContext ctx) {
            ctx.Response.StatusCode = 401;
            return "Hello, Unauthorized World!";
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/401", new Dictionary<string, string>(), 10000, out code);
        Assert.AreEqual(code, HttpStatusCode.Unauthorized);
        Assert.AreEqual(response, "Hello, Unauthorized World!");
    }

    [TestMethod]
    public void Test200Response()
    {
        srv.handler = delegate(HttpListenerContext ctx)
        {
            return "Hello, World!";
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/hello", new Dictionary<string, string>(), 10000, out code);
        Assert.AreEqual(code, HttpStatusCode.OK);
        Assert.AreEqual(response, "Hello, World!");
    }

    [TestMethod]
    public void TestDefaultUserAgent()
    {
        srv.handler = delegate(HttpListenerContext ctx)
        {
            Console.WriteLine(String.Format("User-Agent is: {0}", ctx.Request.UserAgent));
            return ctx.Request.UserAgent;
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/DefaultUserAgent", new Dictionary<string, string>(), 10000, out code);
        Assert.AreEqual(code, HttpStatusCode.OK);
        StringAssert.StartsWith(response, api.DEFAULT_AGENT);
    }

    [TestMethod]
    public void TestCustomUserAgent()
    {
        api = new TestDuoApi(test_ikey, test_skey, test_host, "CustomUserAgent/1.0");
        srv.handler = delegate(HttpListenerContext ctx)
        {
            return ctx.Request.UserAgent;
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/CustomUserAgent", new Dictionary<string, string>(), 10000, out code);
        Assert.AreEqual(code, HttpStatusCode.OK);
        Assert.AreEqual("CustomUserAgent/1.0", response);
    }

    [TestMethod]
    public void TestGetParameterSigning()
    {
        Dictionary<string, string> parameters = new Dictionary<string, string>
        {
            {"param1", "foo"},
            {"param2", "bar"}
        };

        srv.handler = delegate(HttpListenerContext ctx) {
            if (ctx.Request.HttpMethod != "GET")
            {
                return "bad method!";
            }
            if (ctx.Request.Url.AbsolutePath != "/get_params")
            {
                return "bad path!";
            }

            string expected_query_str = DuoApi.CanonicalizeParams(parameters);
            if (("?" + expected_query_str) != ctx.Request.Url.Query)
            {
                return "bad query string!";
            }

            // Sign() is itself tested elsewhere
            string date = ctx.Request.Headers["X-Duo-Date"];
            string expected_signature = api.Sign(
                "GET", "/get_params", expected_query_str, date);
            string authorization = ctx.Request.Headers["Authorization"];
            if (authorization != expected_signature)
            {
                return "bad signature";
            }
            return "OK";
            
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/get_params", parameters, 10000, out code);
        Assert.AreEqual("OK", response);
    }

    [TestMethod]
    public void TestPostParameterSigning()
    {
        Dictionary<string, string> parameters = new Dictionary<string, string>
        {
            {"param1", "foo"},
            {"param2", "bar"}
        };

        srv.handler = delegate(HttpListenerContext ctx)
        {
            if (ctx.Request.HttpMethod != "POST")
            {
                return "bad method!";
            }
            if (ctx.Request.Url.AbsolutePath != "/get_params")
            {
                return "bad path!";
            }
            string expected_body = DuoApi.CanonicalizeParams(parameters);
            string actual_body = (new StreamReader(ctx.Request.InputStream)).ReadToEnd();
            if (expected_body != actual_body)
            {
                return "bad  post body!";
            }

            // Sign() is itself tested elsewhere
            string date = ctx.Request.Headers["X-Duo-Date"];
            string expected_signature = api.Sign(
                "POST", "/get_params", expected_body, date);
            string authorization = ctx.Request.Headers["Authorization"];
            if (authorization != expected_signature)
            {
                return "bad signature";
            }
            return "OK";

        };

        HttpStatusCode code;
        string response = api.ApiCall("POST", "/get_params", parameters, 10000, out code);
        Assert.AreEqual("OK", response);
    }

    [TestMethod]
    public void TestPostParameterSigningCustomDate()
    {
        Dictionary<string, string> parameters = new Dictionary<string, string>
        {
            {"param1", "foo"},
            {"param2", "bar"}
        };

        srv.handler = delegate(HttpListenerContext ctx)
        {
            if (ctx.Request.HttpMethod != "POST")
            {
                return "bad method!";
            }
            if (ctx.Request.Url.AbsolutePath != "/get_params")
            {
                return "bad path!";
            }
            string expected_body = DuoApi.CanonicalizeParams(parameters);
            string actual_body = (new StreamReader(ctx.Request.InputStream)).ReadToEnd();
            if (expected_body != actual_body)
            {
                return "bad post body!";
            }

            string date_header = ctx.Request.Headers["X-Duo-Date"];
            if (date_header != "Mon, 11 Nov 2013 22:34:00 +0000")
            {
                return "bad date!";
            }

            // Sign() is itself tested elsewhere
            string expected_signature = api.Sign(
                "POST", "/get_params", expected_body, date_header);
            string authorization = ctx.Request.Headers["Authorization"];
            if (authorization != expected_signature)
            {
                return "bad signature";
            }
            return "OK";

        };

        DateTime date = new DateTime(2013, 11, 11, 22, 34, 00, DateTimeKind.Utc);
        HttpStatusCode status_code;
        string response = api.ApiCall("POST", "/get_params", parameters, 10000, date, out status_code);
        Assert.AreEqual("OK", response);
    }


    [TestMethod]
    public void TestJsonTimeout()
    {
        srv.handler = delegate(HttpListenerContext ctx)
        {
            Thread.Sleep(2 * 1000);
            return "You should've timed out!";
        };

        try
        {
            string response = api.JSONApiCall<string>("GET", "/timeout", new Dictionary<string, string>(), 500);
            Assert.Fail("Did not raise a Timeout exception!");
        }
        catch (WebException ex)
        {
            Assert.AreEqual(ex.Status, WebExceptionStatus.Timeout);
        }
        catch (Exception ex)
        {
            Assert.Fail("Raised the wrong type of Exception: {0}", ex);
        }
    }

    [TestMethod]
    public void TestValidJsonResponse()
    {
        srv.handler = delegate(HttpListenerContext ctx)
        {
            return "{\"stat\": \"OK\", \"response\": \"hello, world!\"}";
        };
        string response = api.JSONApiCall<string>("GET", "/json_ok", new Dictionary<string,string>());
        Assert.AreEqual(response, "hello, world!");
    }

    [TestMethod]
    public void TestValidJsonPagingResponse()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            return "{\"stat\": \"OK\", \"response\": \"hello, world!\", \"metadata\": {\"next_offset\":10}}";
        };
        var jsonResponse = api.JSONPagingApiCall("GET", "/json_ok", new Dictionary<string, string>(), 0, 10);
        Assert.AreEqual(jsonResponse["response"], "hello, world!");
        var metadata = jsonResponse["metadata"] as Dictionary<string, object>;
        Assert.AreEqual(metadata["next_offset"], 10);
    }
    [TestMethod]
    public void TestErrorJsonResponse()
    {
        srv.handler = delegate(HttpListenerContext ctx)
        {
            ctx.Response.StatusCode = 400;
            return "{\"stat\": \"FAIL\", \"message\": \"Missing required request parameters\", \"code\": 40001, \"message_detail\": \"user_id or username\"}";
        };
        try {
            string response = api.JSONApiCall<string>("GET", "/json_error", new Dictionary<string,string>());
            Assert.Fail("Didn't raise ApiException");
        }
        catch (ApiException e)
        {
            Assert.AreEqual(e.HttpStatus, 400);
            Assert.AreEqual(e.Code, 40001);
            Assert.AreEqual(e.ApiMessage, "Missing required request parameters");
            Assert.AreEqual(e.ApiMessageDetail, "user_id or username");
        }
    }

    [TestMethod]
    public void TestJsonResponseMissingField()
    {
        srv.handler = delegate(HttpListenerContext ctx)
        {
            ctx.Response.StatusCode = 400;
            return "{\"message\": \"Missing required request parameters\", \"code\": 40001, \"message_detail\": \"user_id or username\"}";
        };
        try
        {
            string response = api.JSONApiCall<string>("GET", "/json_missing_field", new Dictionary<string, string>());
            Assert.Fail("Didn't raise ApiException");
        }
        catch (BadResponseException e)
        {
            Assert.AreEqual(e.HttpStatus, 400);
        }
    }

    [TestMethod]
    public void TestJsonUnparseableResponse()
    {
        srv.handler = delegate(HttpListenerContext ctx)
        {
            ctx.Response.StatusCode = 500;
            return "this is not json";
        };
        try
        {
            string response = api.JSONApiCall<string>("GET", "/json_bad", new Dictionary<string, string>());
            Assert.Fail("Didn't raise ApiException");
        }
        catch (BadResponseException e)
        {
            Assert.AreEqual(e.HttpStatus, 500);
        }
    }

    private TestServer srv;
    private Thread srvThread;
    private TestDuoApi api;
}