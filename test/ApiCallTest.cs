using Duo;
using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

// Subclass DuoApi so we can test using HTTP rather than HTTPS
public class TestDuoApi : DuoApi
{
    public TestDuoApi(string ikey, string skey, string host)
        : base(ikey, skey, host, "http")
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
        string responseString = handler(context);

        // write the response
        HttpListenerResponse response = context.Response;
        byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
        response.ContentLength64 = buffer.Length;
        System.IO.Stream output = response.OutputStream;
        output.Write(buffer, 0, buffer.Length);
        output.Close();

        // shut down the listener
        listener.Stop();
    }

    private string ikey;
    private string skey;
    private TestDispatchHandler _handler;
}

[TestFixture]
public class TestApiCall
{
    private const string test_ikey = "DI9FD6NAKXN4B9DTCCB7";
    private const string test_skey = "RScfSuMrpL52TaciEhGtZkGjg8W4JSe5luPL63J8";
    private const string test_host = "localhost:8080";

    [SetUp]
    public void SetUp()
    {
        api = new TestDuoApi(test_ikey, test_skey, test_host);
        srv = new TestServer(test_ikey, test_skey);
        srvThread = new Thread(srv.Run);
        srvThread.Start();
    }

    [TearDown]
    public void CleanUp()
    {
        srvThread.Join();
    }

    [Test]
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

    [Test]
    public void Test200Response()
    {
        srv.handler = delegate(HttpListenerContext ctx)
        {
            return "Hello, World!";
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/hello", new Dictionary<string, string>(), 0, out code);
        Assert.AreEqual(code, HttpStatusCode.OK);
        Assert.AreEqual(response, "Hello, World!");
    }

    [Test]
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

        string response = api.ApiCall("GET", "/get_params", parameters);
        Assert.AreEqual("OK", response);
    }

    [Test]
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

        string response = api.ApiCall("POST", "/get_params", parameters);
        Assert.AreEqual("OK", response);
    }

    [Test]
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
        string response = api.ApiCall("POST", "/get_params", parameters, 0, date, out status_code);
        Assert.AreEqual("OK", response);
    }


    [Test]
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

    [Test]
    public void TestValidJsonResponse()
    {
        srv.handler = delegate(HttpListenerContext ctx)
        {
            return "{\"stat\": \"OK\", \"response\": \"hello, world!\"}";
        };
        string response = api.JSONApiCall<string>("GET", "/json_ok", new Dictionary<string,string>());
        Assert.AreEqual(response, "hello, world!");
    }

    [Test]
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
            Assert.AreEqual(e.http_status, 400);
            Assert.AreEqual(e.code, 40001);
            Assert.AreEqual(e.message, "Missing required request parameters");
            Assert.AreEqual(e.message_detail, "user_id or username");
        }
    }

    [Test]
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
            Assert.AreEqual(e.http_status, 400);
        }
    }

    [Test]
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
            Assert.AreEqual(e.http_status, 500);
        }
    }

    private TestServer srv;
    private Thread srvThread;
    private TestDuoApi api;
}

