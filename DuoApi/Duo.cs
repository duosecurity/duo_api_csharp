/*
 * Copyright (c) 2018 Duo Security
 * All rights reserved
 */

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Web;

namespace Duo
{
	public class DuoApi
    {
        public string DEFAULT_AGENT = "DuoAPICSharp/1.0";

        private const int INITIAL_BACKOFF_MS = 1000;
        private const int MAX_BACKOFF_MS = 32000;
        private const int BACKOFF_FACTOR = 2;
        private const int RATE_LIMIT_HTTP_CODE = 429;
        private string ikey;
        private string skey;
        private string host;
        private string url_scheme;
        private string user_agent;
        private SleepService sleepService;
        private RandomService randomService;
        private bool sslCertValidation = true;
        private X509CertificateCollection customRoots = null;
        
        // TLS 1.0/1.1 deprecation effective June 30, 2023
        // Of the SecurityProtocolType enum, it should be noted that SystemDefault is not available prior to .NET 4.7 and TLS 1.3 is not available prior to .NET 4.8.
        private static SecurityProtocolType SelectSecurityProtocolType
        {
            get
            {
                SecurityProtocolType t;
                if (!Enum.TryParse(ConfigurationManager.AppSettings["DuoAPI_SecurityProtocolType"], out t))
                    return SecurityProtocolType.Tls12;

                return t;
            }
        }

        /// <param name="ikey">Duo integration key</param>
        /// <param name="skey">Duo secret key</param>
        /// <param name="host">Application secret key</param>
        public DuoApi(string ikey, string skey, string host)
            : this(ikey, skey, host, null)
        {
        }

        /// <param name="ikey">Duo integration key</param>
        /// <param name="skey">Duo secret key</param>
        /// <param name="host">Application secret key</param>
        /// <param name="user_agent">HTTP client User-Agent</param>
        public DuoApi(string ikey, string skey, string host, string user_agent)
            : this(ikey, skey, host, user_agent, "https", new ThreadSleepService(), new SystemRandomService())
        {
        }

        protected DuoApi(string ikey, string skey, string host, string user_agent, string url_scheme,
                SleepService sleepService, RandomService randomService)
        {
            this.ikey = ikey;
            this.skey = skey;
            this.host = host;
            this.url_scheme = url_scheme;
            this.sleepService = sleepService;
            this.randomService = randomService;
            if (String.IsNullOrEmpty(user_agent))
            {
                this.user_agent = FormatUserAgent(DEFAULT_AGENT);
            }
            else
            {
                this.user_agent = user_agent;
            }
        }

        ///  <summary>
        /// Disables SSL certificate validation for the API calls the client makes.
        /// Incomptible with UseCustomRootCertificates since certificates will not be checked.
        /// 
        /// THIS SHOULD NEVER BE USED IN A PRODUCTION ENVIRONMENT
        /// </summary>
        /// <returns>The DuoApi</returns>
        public DuoApi DisableSslCertificateValidation()
        {
            sslCertValidation = false;
            return this;
        }

        /// <summary>
        /// Override the set of Duo root certificates used for certificate pinning.  Provide a collection of acceptable root certificates.
        /// 
        /// Incompatible with DisableSslCertificateValidation - if that is enabled, certificate pinning is not done at all. 
        /// </summary>
        /// <param name="customRoots">The custom set of root certificates to trust</param>
        /// <returns>The DuoApi</returns>
        public DuoApi UseCustomRootCertificates(X509CertificateCollection customRoots)
        {
            this.customRoots = customRoots;
            return this;
        }

        public static string FinishCanonicalize(string p)
        {
            // Signatures require upper-case hex digits.
            p = Regex.Replace(p,
                            "(%[0-9A-Fa-f][0-9A-Fa-f])",
                            c => c.Value.ToUpperInvariant());
            // Escape only the expected characters.
            p = Regex.Replace(p,
                            "([!'()*])",
                            c => "%" + Convert.ToByte(c.Value[0]).ToString("X"));
            p = p.Replace("%7E", "~");
            // UrlEncode converts space (" ") to "+". The
            // signature algorithm requires "%20" instead. Actual
            // + has already been replaced with %2B.
            p = p.Replace("+", "%20");
            return p;
        }

        public static string CanonicalizeParams(Dictionary<string, string> parameters)
        {
            var ret = new List<String>();
            foreach (KeyValuePair<string, string> pair in parameters)
            {
                string p = String.Format("{0}={1}",
                                         HttpUtility.UrlEncode(pair.Key),
                                         HttpUtility.UrlEncode(pair.Value));

                p = FinishCanonicalize(p);
                ret.Add(p);
            }
            ret.Sort(StringComparer.Ordinal);
            return string.Join("&", ret.ToArray());
        }


        // handle value as an object eg. next_offset = ["123", "fdajkld"]
        public static string CanonicalizeParams(Dictionary<string, object> parameters)
        {
            var ret = new List<String>();
            foreach (KeyValuePair<string, object> pair in parameters)
            {
                string p = "";
                if (pair.Value.GetType() == typeof(string[]))
                {
                    string[] values = (string[])pair.Value;
                    string value1 = values[0];
                    string value2 = values[1];
                    p = String.Format("{0}={1}&{2}={3}",
                                        HttpUtility.UrlEncode(pair.Key),
                                        HttpUtility.UrlEncode(value1),
                                        HttpUtility.UrlEncode(pair.Key),
                                        HttpUtility.UrlEncode(value2));
                }
                else
                {
                    string val = (string)pair.Value;
                    p = String.Format("{0}={1}",
                                        HttpUtility.UrlEncode(pair.Key),
                                        HttpUtility.UrlEncode(val));
                }
                p = FinishCanonicalize(p);
                ret.Add(p);
            }
            ret.Sort(StringComparer.Ordinal);
            return string.Join("&", ret.ToArray());
        }


        protected string CanonicalizeRequest(string method,
                                             string path,
                                             string canon_params,
                                             string date)
        {
            string[] lines = {
                date,
                method.ToUpperInvariant(),
                this.host.ToLower(),
                path,
                canon_params,
            };
            string canon = String.Join("\n",
                                       lines);
            return canon;
        }

        public string Sign(string method,
                           string path,
                           string canon_params,
                           string date)
        {
            string canon = this.CanonicalizeRequest(method,
                                                    path,
                                                    canon_params,
                                                    date);
            string sig = this.HmacSign(canon);
            string auth = this.ikey + ':' + sig;
            return "Basic " + DuoApi.Encode64(auth);
        }

        public string ApiCall(string method,
                              string path,
                              Dictionary<string, string> parameters)
        {
            HttpStatusCode statusCode;
            return ApiCall(method, path, parameters, 0, DateTime.UtcNow, out statusCode);
        }

        /// <param name="timeout">The request timeout, in milliseconds.
        /// Specify 0 to use the system-default timeout. Use caution if
        /// you choose to specify a custom timeout - some API
        /// calls (particularly in the Auth APIs) will not
        /// return a response until an out-of-band authentication process
        /// has completed. In some cases, this may take as much as a
        /// small number of minutes.</param>
        public string ApiCall(string method,
                              string path,
                              Dictionary<string, string> parameters,
                              int timeout,
                              out HttpStatusCode statusCode)
        {
            return ApiCall(method, path, parameters, 0, DateTime.UtcNow, out statusCode);
        }

        /// <param name="date">The current date and time, used to authenticate
        /// the API request. Typically, you should specify DateTime.UtcNow,
        /// but if you do not wish to rely on the system-wide clock, you may
        /// determine the current date/time by some other means.</param>
        /// <param name="timeout">The request timeout, in milliseconds.
        /// Specify 0 to use the system-default timeout. Use caution if
        /// you choose to specify a custom timeout - some API
        /// calls (particularly in the Auth APIs) will not
        /// return a response until an out-of-band authentication process
        /// has completed. In some cases, this may take as much as a
        /// small number of minutes.</param>
        public string ApiCall(string method,
                              string path,
                              Dictionary<string, string> parameters,
                              int timeout,
                              DateTime date,
                              out HttpStatusCode statusCode)
        {
            string canon_params = DuoApi.CanonicalizeParams(parameters);
            string query = "";
            if (!method.Equals("POST") && !method.Equals("PUT"))
            {
                if (parameters.Count > 0)
                {
                    query = "?" + canon_params;
                }
            }
            string url = string.Format("{0}://{1}{2}{3}",
                                       this.url_scheme,
                                       this.host,
                                       path,
                                       query);

            string date_string = DuoApi.DateToRFC822(date);
            string auth = this.Sign(method, path, canon_params, date_string);



            HttpWebResponse response = AttemptRetriableHttpRequest(
                method, url, auth, date_string, canon_params, timeout);
            StreamReader reader
                = new StreamReader(response.GetResponseStream());
            statusCode = response.StatusCode;
            return reader.ReadToEnd();
        }

        private HttpWebRequest PrepareHttpRequest(String method, String url, String auth, String date,
            String cannonParams, int timeout)
        {
            ServicePointManager.SecurityProtocol = SelectSecurityProtocolType;
            
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.ServerCertificateValidationCallback = GetCertificatePinner();
            request.Method = method;
            request.Accept = "application/json";
            request.Headers.Add("Authorization", auth);
            request.Headers.Add("X-Duo-Date", date);
            request.UserAgent = this.user_agent;

            //todo: Understand, handle and test proxy config

            // If no proxy, check for and use WinHTTP proxy as autoconfig won't pick this up when run from a service
            //if (!HasProxyServer(request))
            //request.Proxy = GetWinhttpProxy();

            if (method.Equals("POST") || method.Equals("PUT"))
            {
                byte[] data = Encoding.UTF8.GetBytes(cannonParams);
                request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = data.Length;
                using (Stream requestStream = request.GetRequestStream())
                {
                    requestStream.Write(data, 0, data.Length);
                }
            }
            if (timeout > 0)
            {
                request.Timeout = timeout;
            }

            return request;
        }

        private RemoteCertificateValidationCallback GetCertificatePinner()
        {
            if (!sslCertValidation)
            {
                // Pinner that effectively disables cert pinning by always returning true
                return CertificatePinnerFactory.GetCertificateDisabler();
            }

            if (customRoots != null)
            {
                return CertificatePinnerFactory.GetCustomRootCertificatesPinner(customRoots);
            }

            return CertificatePinnerFactory.GetDuoCertificatePinner();
        }

        private HttpWebResponse AttemptRetriableHttpRequest(
            String method, String url, String auth, String date, String cannonParams, int timeout)
        {
            int backoffMs = INITIAL_BACKOFF_MS;
            while (true)
            {
                // Do the request and process the result.
                HttpWebRequest request = PrepareHttpRequest(method, url, auth, date, cannonParams, timeout);
                HttpWebResponse response;
                try
                {
                    response = (HttpWebResponse)request.GetResponse();
                }
                catch (WebException ex)
                {
                    response = (HttpWebResponse)ex.Response;
                    if (response == null)
                    {
                        throw;
                    }
                }

                if (response.StatusCode != (HttpStatusCode)RATE_LIMIT_HTTP_CODE || backoffMs > MAX_BACKOFF_MS)
                {
                    return response;
                }

                sleepService.Sleep(backoffMs + randomService.GetInt(1001));
                backoffMs *= BACKOFF_FACTOR;
            }
        }

        /// <param name="date">The current date and time, used to authenticate
        /// the API request. Typically, you should specify DateTime.UtcNow,
        /// but if you do not wish to rely on the system-wide clock, you may
        /// determine the current date/time by some other means.</param>
        /// <param name="timeout">The request timeout, in milliseconds.
        /// Specify 0 to use the system-default timeout. Use caution if
        /// you choose to specify a custom timeout - some API
        /// calls (particularly in the Auth APIs) will not
        /// return a complete JSON response.</param>
        /// raises if JSON response indicates an error
        private T BaseJSONApiCall<T>(string method,
                                string path,
                                Dictionary<string, string> parameters,
                                int timeout,
                                DateTime date,
                                out PagingInfo metaData)
        {
            HttpStatusCode statusCode;
            string res = this.ApiCall(method, path, parameters, timeout, date, out statusCode);


            try
            {
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };

                options.Converters.Add(new JsonStringEnumConverter());

                var dict = JsonSerializer.Deserialize<DataEnvelope<T>>(res, options);
                if (dict.stat == DuoApiResponseStatus.Ok)
                {
                    metaData = dict.metadata;
                    return dict.response;
                }
                else
                {

                    int code = dict.code.GetValueOrDefault();

                    throw new ApiException(code,
                                           (int)statusCode,
                                           dict.message,
                                           dict.message_detail);
                }
            }
            catch (ApiException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new BadResponseException((int)statusCode, e);
            }
        }

        public T JSONApiCall<T>(string method,
                                string path,
                                Dictionary<string, string> parameters)
            where T : class
        {
            return JSONApiCall<T>(method, path, parameters, 0, DateTime.UtcNow);
        }

        /// <param name="timeout">The request timeout, in milliseconds.
        /// Specify 0 to use the system-default timeout. Use caution if
        /// you choose to specify a custom timeout - some API
        /// calls (particularly in the Auth APIs) will not
        /// return a response until an out-of-band authentication process
        /// has completed. In some cases, this may take as much as a
        /// small number of minutes.</param>
        public T JSONApiCall<T>(string method,
                                string path,
                                Dictionary<string, string> parameters,
                                int timeout)
            where T : class
        {
            return JSONApiCall<T>(method, path, parameters, timeout, DateTime.UtcNow);
        }

        /// <param name="date">The current date and time, used to authenticate
        /// the API request. Typically, you should specify DateTime.UtcNow,
        /// but if you do not wish to rely on the system-wide clock, you may
        /// determine the current date/time by some other means.</param>
        /// <param name="timeout">The request timeout, in milliseconds.
        /// Specify 0 to use the system-default timeout. Use caution if
        /// you choose to specify a custom timeout - some API
        /// calls (particularly in the Auth APIs) will not
        /// return a response until an out-of-band authentication process
        /// has completed. In some cases, this may take as much as a
        /// small number of minutes.</param>
        public T JSONApiCall<T>(string method,
                                string path,
                                Dictionary<string, string> parameters,
                                int timeout,
                                DateTime date)
            where T : class
        {
            return BaseJSONApiCall<T>(method, path, parameters, timeout, date, out _);
        }

        public T JSONPagingApiCall<T>(string method,
                               string path,
                               Dictionary<string, string> parameters,
                               int offset,
                               int limit,
                               out PagingInfo metaData)
        {
            return JSONPagingApiCall<T>(method, path, parameters, offset, limit, 0, DateTime.UtcNow, out metaData);
        }

        /// <param name="date">The current date and time, used to authenticate
        /// the API request. Typically, you should specify DateTime.UtcNow,
        /// but if you do not wish to rely on the system-wide clock, you may
        /// determine the current date/time by some other means.</param>
        /// <param name="timeout">The request timeout, in milliseconds.
        /// Specify 0 to use the system-default timeout. Use caution if
        /// you choose to specify a custom timeout - some API
        /// calls (particularly in the Auth APIs) will not
        /// return a response until an out-of-band authentication process
        /// has completed. In some cases, this may take as much as a
        /// small number of minutes.</param>
        /// <param name="offset">The offset of the first record in the next
        /// page of results within the total result set.</param>
        /// <param name="limit">The number of records you would like returned
        /// with this request.  The service is free to return a different
        /// number.  You should use the 'next_offset' from the returned
        /// metadata to pick the offset for the next page.</param>
        /// return a JSON dictionary with top level keys: stat, response, metadata.
        /// The actual requested data is in 'response'.  'metadata' contains a
        /// 'next_offset' key which should be used to fetch the next page.
        public T JSONPagingApiCall<T>(string method,
                                string path,
                                Dictionary<string, string> parameters,
                                int offset,
                                int limit,
                                int timeout,
                                DateTime date,
                                out PagingInfo metaData)
        {
            // copy parameters so we don't cause any side-effects
            parameters = new Dictionary<string, string>(parameters);
            parameters["offset"] = offset.ToString(); // overrides caller value
            parameters["limit"] = limit.ToString();

            return this.BaseJSONApiCall<T>(method, path, parameters, timeout, date, out metaData);
        }


        /// Helper to format a User-Agent string with some information about
        /// the operating system / .NET runtime
        /// <param name="product_name">e.g. "FooClient/1.0"</param>
        public static string FormatUserAgent(string product_name)
        {
            return String.Format(
                 "{0} ({1}; .NET {2})", product_name, System.Environment.OSVersion,
                 System.Environment.Version);
        }

        #region Private Methods
        private string HmacSign(string data)
        {
            byte[] key_bytes = ASCIIEncoding.ASCII.GetBytes(this.skey);
            HMACSHA512 hmac = new HMACSHA512(key_bytes);

            byte[] data_bytes = ASCIIEncoding.ASCII.GetBytes(data);
            hmac.ComputeHash(data_bytes);

            string hex = BitConverter.ToString(hmac.Hash);
            return hex.Replace("-", "").ToLower();
        }

        private static string Encode64(string plaintext)
        {
            byte[] plaintext_bytes = ASCIIEncoding.ASCII.GetBytes(plaintext);
            string encoded = System.Convert.ToBase64String(plaintext_bytes);
            return encoded;
        }

        private static string DateToRFC822(DateTime date)
        {
            // Can't use the "zzzz" format because it adds a ":"
            // between the offset's hours and minutes.
            string date_string = date.ToString(
                "ddd, dd MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture);
            int offset = 0;
            // set offset if input date is not UTC time.
            if (date.Kind != DateTimeKind.Utc)
            {
                offset = TimeZoneInfo.Local.GetUtcOffset(date).Hours;
            }
            string zone;
            // + or -, then 0-pad, then offset, then more 0-padding.
            if (offset < 0)
            {
                offset *= -1;
                zone = "-";
            }
            else
            {
                zone = "+";
            }
            zone += offset.ToString(CultureInfo.InvariantCulture).PadLeft(2, '0');
            date_string += " " + zone.PadRight(5, '0');
            return date_string;
        }

        ///// <summary>
        ///// Gets the WinHTTP proxy.
        ///// </summary>
        ///// <remarks>
        ///// Normally, C# picks up these proxy settings by default, but when run under the SYSTEM account, it does not.
        ///// </remarks>
        ///// <returns></returns>
        //private static System.Net.WebProxy GetWinhttpProxy()
        //{
        //    string[] proxyServerNames = null;
        //    string primaryProxyServer = null;
        //    string[] bypassHostnames = null;
        //    bool enableLocalBypass = false;
        //    System.Net.WebProxy winhttpProxy = null;

        //    // Has a proxy been configured?
        //    // No.  Is a WinHTTP proxy set?
        //    int internetHandle = WinHttpOpen("DuoTest", WinHttp_Access_Type.WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, null, null, 0);
        //    if (internetHandle != 0)
        //    {
        //        // Yes, use it.  This is normal when run under the SYSTEM account and a WinHTTP proxy is configured.  When run as a normal user,
        //        // the Proxy property will already be configured correctly.  To resolve this for SYSTEM, manually read proxy settings and configure.
        //        var proxyInfo = new WINHTTP_PROXY_INFO();
        //        WinHttpGetDefaultProxyConfiguration(proxyInfo);
        //        if (proxyInfo.lpszProxy != null)
        //        {
        //            if (proxyInfo.lpszProxy != null)
        //            {
        //                proxyServerNames = proxyInfo.lpszProxy.Split(new char[] { ' ', '\t', ';' });
        //                if ((proxyServerNames == null) || (proxyServerNames.Length == 0))
        //                    primaryProxyServer = proxyInfo.lpszProxy;
        //                else
        //                    primaryProxyServer = proxyServerNames[0];
        //            }
        //            if (proxyInfo.lpszProxyBypass != null)
        //            {
        //                bypassHostnames = proxyInfo.lpszProxyBypass.Split(new char[] { ' ', '\t', ';' });
        //                if ((bypassHostnames == null) || (bypassHostnames.Length == 0))
        //                    bypassHostnames = new string[] { proxyInfo.lpszProxyBypass };
        //                if (bypassHostnames != null)
        //                    enableLocalBypass = bypassHostnames.Contains("local", StringComparer.InvariantCultureIgnoreCase);
        //            }
        //            if (primaryProxyServer != null)
        //                winhttpProxy = new System.Net.WebProxy(proxyServerNames[0], enableLocalBypass, bypassHostnames);
        //        }
        //        WinHttpCloseHandle(internetHandle);
        //        internetHandle = 0;
        //    }
        //    else
        //    {
        //        throw new Exception(String.Format("WinHttp init failed {0}", System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
        //    }

        //    return winhttpProxy;
        //}

        ///// <summary>
        ///// Determines if the specified web request is using a proxy server.
        ///// </summary>
        ///// <remarks>
        ///// If no proxy is set, the Proxy member is typically non-null and set to an object type that includes but hides IWebProxy with no address,
        ///// so it cannot be inspected.  Resolving this requires reflection to extract the hidden webProxy object and check it's Address member.
        ///// </remarks>
        ///// <param name="requestObject">Request to check</param>
        ///// <returns>TRUE if a proxy is in use, else FALSE</returns>
        //public static bool HasProxyServer(HttpWebRequest requestObject)
        //{
        //    WebProxy actualProxy = null;
        //    bool hasProxyServer = false;

        //    if (requestObject.Proxy != null)
        //    {
        //        // WebProxy is described as the base class for IWebProxy, so we should always see this type as the field is initialized by the framework.
        //        if (!(requestObject.Proxy is WebProxy))
        //        {
        //            var webProxyField = requestObject.Proxy.GetType().GetField("webProxy", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public);
        //            if (webProxyField != null)
        //                actualProxy = webProxyField.GetValue(requestObject.Proxy) as WebProxy;
        //        }
        //        else
        //        {
        //            actualProxy = requestObject.Proxy as WebProxy;
        //        }
        //        hasProxyServer = (actualProxy.Address != null);
        //    }
        //    else
        //    {
        //        hasProxyServer = false;
        //    }

        //    return hasProxyServer;
        //}
        #endregion Private Methods

        #region Private DllImport
        private enum WinHttp_Access_Type
        {
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0,
            WINHTTP_ACCESS_TYPE_NO_PROXY = 1,
            WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3,
            /// <summary>
            /// Undocumented; supported on Win8.1+ per NET framework source.
            /// </summary>
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4
        }

        [StructLayout(LayoutKind.Sequential)]
        private class WINHTTP_PROXY_INFO
        {
            public int dwAccessType;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpszProxy;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpszProxyBypass;
        }
        [DllImport("winhttp.dll", CharSet = CharSet.Unicode)]
        private static extern bool WinHttpGetDefaultProxyConfiguration([In, Out] WINHTTP_PROXY_INFO proxyInfo);

        [DllImport("winhttp.dll", CharSet = CharSet.Unicode)]
        private static extern int WinHttpOpen([MarshalAs(UnmanagedType.LPWStr)] string pwszUserAgent,
          WinHttp_Access_Type dwAccessType,
          [MarshalAs(UnmanagedType.LPWStr)] string pwszProxyName,
          [MarshalAs(UnmanagedType.LPWStr)] string pwszProxyBypass,
          int dwFlags);

        [DllImport("winhttp.dll", CharSet = CharSet.Unicode)]
        private static extern bool WinHttpCloseHandle(int hInternet);
        #endregion Private DllImport
    }

    [Serializable]
    public class DuoException : Exception
    {
        public int HttpStatus { get; private set; }

        public DuoException(int http_status, string message, Exception inner)
            : base(message, inner)
        {
            this.HttpStatus = http_status;
        }

        protected DuoException(System.Runtime.Serialization.SerializationInfo info,
                               System.Runtime.Serialization.StreamingContext ctxt)
            : base(info, ctxt)
        { }
    }

    [Serializable]
    public class ApiException : DuoException
    {
        public int Code { get; private set; }
        public string ApiMessage { get; private set; }
        public string ApiMessageDetail { get; private set; }

        public ApiException(int code,
                            int http_status,
                            string api_message,
                            string api_message_detail)
            : base(http_status, FormatMessage(code, api_message, api_message_detail), null)
        {
            this.Code = code;
            this.ApiMessage = api_message;
            this.ApiMessageDetail = api_message_detail;
        }

        protected ApiException(System.Runtime.Serialization.SerializationInfo info,
                               System.Runtime.Serialization.StreamingContext ctxt)
            : base(info, ctxt)
        { }

        private static string FormatMessage(int code,
                                            string api_message,
                                            string api_message_detail)
        {
            return String.Format(
                "Duo API Error {0}: '{1}' ('{2}')", code, api_message, api_message_detail);
        }
    }

    [Serializable]
    public class BadResponseException : DuoException
    {
        public BadResponseException(int http_status, Exception inner)
            : base(http_status, FormatMessage(http_status, inner), inner)
        { }

        protected BadResponseException(System.Runtime.Serialization.SerializationInfo info,
                                       System.Runtime.Serialization.StreamingContext ctxt)
            : base(info, ctxt)
        { }

        private static string FormatMessage(int http_status, Exception inner)
        {
            string inner_message = "(null)";
            if (inner != null)
            {
                inner_message = String.Format("'{0}'", inner.Message);
            }
            return String.Format(
                "Got error {0} with HTTP Status {1}", inner_message, http_status);
        }
    }

    public interface SleepService
    {
        void Sleep(int ms);
    }

    public interface RandomService
    {
        int GetInt(int maxInt);
    }

    class ThreadSleepService : SleepService
    {
        public void Sleep(int ms)
        {
            System.Threading.Thread.Sleep(ms);
        }
    }

    class SystemRandomService : RandomService
    {
        private Random rand = new Random();

        public int GetInt(int maxInt)
        {
            return rand.Next(maxInt);
        }
    }
}
