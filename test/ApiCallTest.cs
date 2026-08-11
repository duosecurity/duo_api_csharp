using Duo;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.IO;
using Xunit;

// Subclass DuoApi so we can test using HTTP rather than HTTPS
public class TestDuoApi : DuoApi
{
    public MockSleeper sleeper;
    public MockRandom random;
    public TestDuoApi(string ikey, string skey, string host)
        : this(ikey, skey, host, null)
    {
    }
    public TestDuoApi(string ikey, string skey, string host, string user_agent)
        : this(ikey, skey, host, user_agent, new MockSleeper(), new MockRandom())
    {
    }

    public TestDuoApi(string ikey, string skey, string host, string user_agent, MockSleeper sleeper, MockRandom random)
        : base(ikey, skey, host, user_agent, "http", sleeper, random)
    {
        this.sleeper = sleeper;
        this.random = random;
    }
}

public class MockSleeper : SleepService
{
    public List<long> sleepCalls = new List<long>();

    public void Sleep(int ms)
    {
        sleepCalls.Add(ms);
    }
}

public class MockRandom : RandomService
{
    public List<int> randomCalls = new List<int>();

    public int GetInt(int maxInt)
    {
        randomCalls.Add(maxInt);
        return 123;
    }
}

public class TestServer
{
    public int requestsToHandle = 1;

    /// <summary>
    /// The loopback port this server is listening on. Chosen dynamically rather than
    /// fixed, because the test project multi-targets and `dotnet test` runs the net48
    /// and net8.0 test hosts concurrently; a fixed port makes the second host fail to
    /// register its HttpListener prefix and crash the run.
    /// </summary>
    public int Port { get; private set; }

    public TestServer(string ikey, string skey)
    {
        this.ikey = ikey;
        this.skey = skey;

        // Bind in the constructor so the port is known (and the socket already
        // accepting) before the caller builds a client against it.
        this.Port = FindFreePort();
        this.listener = new HttpListener();
        this.listener.Prefixes.Add(String.Format("http://localhost:{0}/", this.Port));
        this.listener.Start();
    }

    /// <summary>
    /// Ask the OS for an unused loopback port by binding port 0 and releasing it.
    /// </summary>
    private static int FindFreePort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        try
        {
            return ((IPEndPoint)probe.LocalEndpoint).Port;
        }
        finally
        {
            probe.Stop();
        }
    }

    public delegate string TestDispatchHandler(HttpListenerContext ctx);
    public TestDispatchHandler handler
    {

        get
        {
            lock (this)
            {
                return this._handler;
            }
        }
        set
        {
            lock (this)
            {
                this._handler = value;
            }
        }
    }

    public HttpListener listener;

    public void Run()
    {
        try
        {
            HandleRequests();
        }
        catch (Exception)
        {
            // The listener was stopped or disposed while we were waiting for a request.
            // This is normal when a test finishes early, and must not be allowed to
            // escape and crash the test host.
        }
        finally
        {
            try
            {
                this.listener.Stop();
            }
            catch (Exception)
            {
                // Already stopped.
            }
        }
    }

    private void HandleRequests()
    {
        for (int i = 0; i < requestsToHandle; i++)
        {
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

            // Write the response. This runs on a background thread, so any failure here
            // has to be swallowed: an unhandled exception would tear down the whole test
            // host. Writing can legitimately fail when the client has already given up
            // (TestJsonTimeout) or stopped the listener from under us.
            try
            {
                HttpListenerResponse response = context.Response;
                System.IO.Stream output = response.OutputStream;

                if (!String.IsNullOrEmpty(responseString))
                {
                    byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
                    response.ContentLength64 = buffer.Length;
                    output.Write(buffer, 0, buffer.Length);
                }
                output.Close();
            }
            catch (Exception)
            {
                // Client went away or the listener was stopped; nothing to report.
            }
        }
    }

    private string ikey;
    private string skey;
    private TestDispatchHandler _handler;
}
public class TestApiCall
{
    private const string test_ikey = "DI9FD6NAKXN4B9DTCCB7";
    private const string test_skey = "RScfSuMrpL52TaciEhGtZkGjg8W4JSe5luPL63J8";

    private readonly string test_host;

    private TestServer srv;
    private Thread srvThread;
    private TestDuoApi api;

    /// <summary>
    ///
    /// </summary>
    public TestApiCall()
    {
        // Start the server first: it picks its own port, which the client then targets.
        srv = new TestServer(test_ikey, test_skey);
        test_host = "localhost:" + srv.Port;
        api = new TestDuoApi(test_ikey, test_skey, test_host);
        srvThread = new Thread(srv.Run);
        srvThread.Start();
    }

    ~TestApiCall()
    {
        srvThread.Join();
    }

    [Fact]
    public void Test401Response()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            ctx.Response.StatusCode = 401;
            return "Hello, Unauthorized World!";
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/401", new Dictionary<string, string>(), 10000, out code);
        Assert.Equal(HttpStatusCode.Unauthorized, code);
        Assert.Equal("Hello, Unauthorized World!", response);
    }

    [Fact]
    public void Test200Response()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            return "Hello, World!";
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/hello", new Dictionary<string, string>(), 10000, out code);
        Assert.Equal(HttpStatusCode.OK, code);
        Assert.Equal("Hello, World!", response);
    }

    [Fact]
    public void TestDefaultUserAgent()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            Console.WriteLine(String.Format("User-Agent is: {0}", ctx.Request.UserAgent));
            return ctx.Request.UserAgent;
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/DefaultUserAgent", new Dictionary<string, string>(), 10000, out code);
        Assert.Equal(HttpStatusCode.OK, code);
        Assert.StartsWith(api.DEFAULT_AGENT, response);
        Assert.Contains(DuoApi.CA_BUNDLE_VERSION, response);
        Assert.EndsWith("(ca_pinning=enabled)", response);
    }

    [Fact]
    public void TestCustomUserAgent()
    {
        api = new TestDuoApi(test_ikey, test_skey, test_host, "CustomUserAgent/1.0");
        srv.handler = delegate (HttpListenerContext ctx)
        {
            return ctx.Request.UserAgent;
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/CustomUserAgent", new Dictionary<string, string>(), 10000, out code);
        Assert.Equal(HttpStatusCode.OK, code);
        Assert.Equal("CustomUserAgent/1.0 " + DuoApi.CA_BUNDLE_VERSION + " (ca_pinning=enabled)", response);
    }

    [Fact]
    public void TestUserAgentCaPinningDisabled()
    {
        api = new TestDuoApi(test_ikey, test_skey, test_host, "CustomUserAgent/1.0");
        api.DisableCaPinning();
        srv.handler = delegate (HttpListenerContext ctx)
        {
            return ctx.Request.UserAgent;
        };

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/CaPinningDisabled", new Dictionary<string, string>(), 10000, out code);
        Assert.Equal(HttpStatusCode.OK, code);
        Assert.Equal("CustomUserAgent/1.0 " + DuoApi.CA_BUNDLE_VERSION + " (ca_pinning=disabled)", response);
    }

    [Fact]
    public void TestGetParameterSigning()
    {
        Dictionary<string, string> parameters = new Dictionary<string, string>
        {
            {"param1", "foo"},
            {"param2", "bar"}
        };

        srv.handler = delegate (HttpListenerContext ctx)
        {
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
        Assert.Equal("OK", response);
    }

    [Fact]
    public void TestPostParameterSigning()
    {
        Dictionary<string, string> parameters = new Dictionary<string, string>
        {
            {"param1", "foo"},
            {"param2", "bar"}
        };

        srv.handler = delegate (HttpListenerContext ctx)
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
        Assert.Equal("OK", response);
    }

    [Fact]
    public void TestPostParameterSigningCustomDate()
    {
        Dictionary<string, string> parameters = new Dictionary<string, string>
        {
            {"param1", "foo"},
            {"param2", "bar"}
        };

        srv.handler = delegate (HttpListenerContext ctx)
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
        Assert.Equal("OK", response);
    }


    [Fact]
    public void TestJsonTimeout()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            Thread.Sleep(2 * 1000);
            return "You should've timed out!";
        };

        var ex = Record.Exception(() =>
        {
            string response = api.JSONApiCall<string>("GET", "/timeout", new Dictionary<string, string>(), 500);
        });

        var we = Assert.IsType<WebException>(ex);
        Assert.Equal(WebExceptionStatus.Timeout, we.Status);

        // Tear down this test's server, which is still sitting in its handler sleep.
        srv.listener.Stop();
    }

    [Fact]
    public void TestValidJsonResponse()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            return "{\"stat\": \"OK\", \"response\": \"hello, world!\"}";
        };
        string response = api.JSONApiCall<string>("GET", "/json_ok", new Dictionary<string, string>());
        Assert.Equal("hello, world!", response);
    }

    [Fact]
    public void TestValidJsonPagingResponseNoParameters()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            return "{\"stat\": \"OK\", \"response\": \"hello, world!\", \"metadata\": {\"next_offset\":10}}";
        };
        var parameters = new Dictionary<string, string>();
        var jsonResponse = api.JSONPagingApiCall("GET", "/json_ok", parameters, 0, 10);
        Assert.Equal("hello, world!", jsonResponse["response"]);
        var metadata = jsonResponse["metadata"] as Dictionary<string, object>;
        Assert.Equal(10, metadata["next_offset"]);
        // make sure parameters was not changed as a side-effect
        Assert.Empty(parameters);
    }

    [Fact]
    public void TestValidJsonPagingResponseExistingParameters()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            return "{\"stat\": \"OK\", \"response\": \"hello, world!\", \"metadata\": {}}";
        };
        var parameters = new Dictionary<string, string>()
        {
            {"offset", "0"},
            {"limit", "10"}
        };
        var jsonResponse = api.JSONPagingApiCall("GET", "/json_ok", parameters, 10, 20);
        Assert.Equal("hello, world!", jsonResponse["response"]);
        var metadata = jsonResponse["metadata"] as Dictionary<string, object>;
        Assert.False(metadata.ContainsKey("next_offset"));
        // make sure parameters was not changed as a side-effect
        Assert.Equal(2, parameters.Count);
        Assert.Equal("0", parameters["offset"]);
        Assert.Equal("10", parameters["limit"]);
    }

    [Fact]
    public void TestErrorJsonResponse()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            ctx.Response.StatusCode = 400;
            return "{\"stat\": \"FAIL\", \"message\": \"Missing required request parameters\", \"code\": 40001, \"message_detail\": \"user_id or username\"}";
        };

        var ex = Record.Exception(() =>
        {
            string response = api.JSONApiCall<string>("GET", "/json_error", new Dictionary<string, string>());
        });

        Assert.NotNull(ex);
        var e = Assert.IsType<ApiException>(ex);


        Assert.Equal(400, e.HttpStatus);
        Assert.Equal(40001, e.Code);
        Assert.Equal("Missing required request parameters", e.ApiMessage);
        Assert.Equal("user_id or username", e.ApiMessageDetail);

    }

    [Fact]
    public void TestJsonResponseMissingField()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            ctx.Response.StatusCode = 400;
            return "{\"message\": \"Missing required request parameters\", \"code\": 40001, \"message_detail\": \"user_id or username\"}";
        };

        var ex = Record.Exception(() =>
        {
            string response = api.JSONApiCall<string>("GET", "/json_missing_field", new Dictionary<string, string>());
        });

        Assert.NotNull(ex);
        var e = Assert.IsType<BadResponseException>(ex);

        Assert.Equal(400, e.HttpStatus);

    }

    [Fact]
    public void TestJsonUnparseableResponse()
    {
        srv.handler = delegate (HttpListenerContext ctx)
        {
            ctx.Response.StatusCode = 500;
            return "this is not json";
        };
        var ex = Record.Exception(() =>
        {
            string response = api.JSONApiCall<string>("GET", "/json_bad", new Dictionary<string, string>());
        });

        Assert.NotNull(ex);
        var e = Assert.IsType<BadResponseException>(ex);
        Assert.Equal(500, e.HttpStatus);

    }

    [Fact]
    public void TestRateLimitThenSuccess()
    {
        List<int> statusCodes = new List<int>() { 429, 200 };
        int callCount = 0;
        srv.handler = delegate (HttpListenerContext ctx)
        {
            callCount++;
            ctx.Response.StatusCode = statusCodes[0];
            statusCodes.RemoveAt(0);
            return "foobar";
        };
        srv.requestsToHandle = 2;

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/hello", new Dictionary<string, string>(), 10000, out code);

        Assert.Equal(HttpStatusCode.OK, code);
        Assert.Single(api.sleeper.sleepCalls);
        Assert.Equal(1123, api.sleeper.sleepCalls[0]);
        Assert.Single(api.random.randomCalls);
        Assert.Equal(1001, api.random.randomCalls[0]);
    }

    [Fact]
    public void TestRateLimitedCompletely()
    {
        List<int> statusCodes = new List<int>() { 429, 429, 429, 429, 429, 429, 429 };
        int callCount = 0;
        srv.handler = delegate (HttpListenerContext ctx)
        {
            callCount++;
            ctx.Response.StatusCode = statusCodes[0];
            statusCodes.RemoveAt(0);
            return "foobar";
        };
        srv.requestsToHandle = 7;

        HttpStatusCode code;
        string response = api.ApiCall("GET", "/hello", new Dictionary<string, string>(), 10000, out code);

        Assert.Equal(code, (HttpStatusCode)429);
        Assert.Equal(7, callCount);
        Assert.Equal(6, api.sleeper.sleepCalls.Count);
        Assert.Equal(1123, api.sleeper.sleepCalls[0]);
        Assert.Equal(2123, api.sleeper.sleepCalls[1]);
        Assert.Equal(4123, api.sleeper.sleepCalls[2]);
        Assert.Equal(8123, api.sleeper.sleepCalls[3]);
        Assert.Equal(16123, api.sleeper.sleepCalls[4]);
        Assert.Equal(32123, api.sleeper.sleepCalls[5]);

        Assert.Equal(6, api.random.randomCalls.Count);
        Assert.Equal(1001, api.random.randomCalls[0]);
        Assert.Equal(1001, api.random.randomCalls[1]);
        Assert.Equal(1001, api.random.randomCalls[2]);
        Assert.Equal(1001, api.random.randomCalls[3]);
        Assert.Equal(1001, api.random.randomCalls[4]);
        Assert.Equal(1001, api.random.randomCalls[5]);
    }
}