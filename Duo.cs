/*
 * Copyright (c) 2013 Duo Security
 * All rights reserved, all wrongs reversed.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text;
using System.Web.Script.Serialization;
using System.Web;

namespace Duo
{
    public class DuoApi
    {
        private string ikey;
        private string skey;
        private string host;

        /// <param name="ikey">Duo integration key</param>
        /// <param name="skey">Duo secret key</param>
        /// <param name="host">Application secret key</param>
        public DuoApi(string ikey, string skey, string host)
        {
            this.ikey = ikey;
            this.skey = skey;
            this.host = host;
        }

        public static string CanonicalizeParams(Dictionary<string, string> parameters)
        {
            var ret = new List<String>();
            foreach (KeyValuePair<string, string> pair in parameters)
            {
                string p = String.Format("{0}={1}",
                                         HttpUtility.UrlEncode(pair.Key),
                                         HttpUtility.UrlEncode(pair.Value));
                // Signatures require upper-case hex digits.
                p = Regex.Replace(p,
                                  "(%[0-9A-Fa-f][0-9A-Fa-f])",
                                  c => c.Value.ToUpper());
                // Escape only the expected characters.
                p = Regex.Replace(p,
                                  "([!'()*])",
                                  c => "%" + Convert.ToByte(c.Value[0]).ToString("x").ToUpper());
                p = p.Replace("%7E", "~");
                // UrlEncode converts space (" ") to "+". The
                // signature algorithm requires "%20" instead. Actual
                // + has already been replaced with %2B.
                p = p.Replace("+", "%20");
                ret.Add(p);
            }
            ret.Sort();
            return string.Join("&", ret.ToArray());
        }

        protected string CanonicalizeRequest(string method,
                                             string path,
                                             string canon_params,
                                             string date)
        {
            string[] lines = {
                date,
                method.ToUpper(),
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
            string canon_params = DuoApi.CanonicalizeParams(parameters);
            string query = "";
            if (! method.Equals("POST") && ! method.Equals("PUT"))
            {
                if (parameters.Count > 0)
                {
                    query = "?" + canon_params;
                }
            }
            string url = string.Format("https://{0}{1}{2}",
                                       this.host,
                                       path,
                                       query);

            string date = DuoApi.DateToRFC822(DateTime.Now);
            string auth = this.Sign(method, path, canon_params, date);

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = method;
            request.Accept = "application/json";
            request.Headers.Add("Authorization: " + auth);

            // Use reflection (or .NET 4's request.Date property) to
            // overwrite the generated Date header. It must parse to
            // the exact same timestamp used when signing.
            Type type = request.Headers.GetType();
            MethodInfo add_method
                = type.GetMethod("AddWithoutValidate",
                                 (BindingFlags.Instance
                                  | BindingFlags.NonPublic));
            add_method.Invoke(request.Headers,
                              new[] { "Date", date });

            if (method.Equals("POST") || method.Equals("PUT"))
            {
                byte[] data = Encoding.UTF8.GetBytes(canon_params);
                request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = data.Length;
                using (Stream requestStream = request.GetRequestStream())
                {
                    requestStream.Write(data, 0, data.Length);
                }
            }

            // Do the request and process the result.
            WebResponse response;
            try
            {
                response = request.GetResponse();
            }
            catch (WebException ex)
            {
                response = ex.Response;
            }
            StreamReader reader
                = new StreamReader(response.GetResponseStream());
            return reader.ReadToEnd();
        }

        public T JSONApiCall<T>(string method,
                                string path,
                                Dictionary<string, string> parameters)
            where T : class
        {
            string res = this.ApiCall(method, path, parameters);
            var jss = new JavaScriptSerializer();
            var dict = jss.Deserialize<Dictionary<string, object>>(res);
            if (dict["stat"] as string == "OK")
            {
                return dict["response"] as T;
            }
            else
            {
                int? check = dict["code"] as int?;
                int code;
                if (check.HasValue)
                {
                    code = check.Value;
                }
                else
                {
                    code = 0;
                }
                String message_detail = "";
                if (dict.ContainsKey("message_detail"))
                {
                    message_detail = dict["message_detail"] as string;
                }
                throw new ApiException(code,
                                       dict["message"] as string,
                                       message_detail);
            }
        }

        private string HmacSign(string data)
        {
            byte[] key_bytes = ASCIIEncoding.ASCII.GetBytes(this.skey);
            HMACSHA1 hmac = new HMACSHA1(key_bytes);

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
            string date_string = date.ToString("ddd, dd MMM yyyy HH:mm:ss");
            int offset = TimeZone.CurrentTimeZone.GetUtcOffset(date).Hours;
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
            zone += offset.ToString().PadLeft(2, '0');
            date_string += " " + zone.PadRight(5, '0');
            return date_string;
        }
    }

    [Serializable]
    public class ApiException : Exception
    {
        public int code { get; private set; }
        public string message { get; private set; }
        public string message_detail { get; private set; }

        public ApiException(int code,
                            string message,
                            string message_detail) {
            this.code = code;
            this.message = message;
            this.message_detail = message_detail;
        }

        protected ApiException(System.Runtime.Serialization.SerializationInfo info,
                               System.Runtime.Serialization.StreamingContext ctxt)
            : base(info, ctxt)
        { }
    }
}
