using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using ARMClient.Authentication.AADAuthentication;
using ARMClient.Authentication.Contracts;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ARMClient.Authentication.Utilities
{
    public static class Utils
    {
        static TraceListener _traceListener;

        public static TraceListener Trace
        {
            get { return _traceListener ?? DefaultTraceListener.Default; }
        }

        public static string GetDefaultToken()
        {
            return Environment.GetEnvironmentVariable("ARMCLIENT_TOKEN");
        }

        public static string GetLoginTenant()
        {
            return Environment.GetEnvironmentVariable("ARMCLIENT_TENANT") ?? Constants.AADCommonTenant;
        }

        public static AzureEnvironments GetDefaultEnv(AzureEnvironments lastResort = AzureEnvironments.Prod)
        {
            AzureEnvironments env;
            return Enum.TryParse<AzureEnvironments>(Environment.GetEnvironmentVariable("ARMCLIENT_ENV"), true, out env) ? env : lastResort;
        }

        public static string GetDefaultCachePath()
        {
            return Environment.GetEnvironmentVariable("ARMCLIENT_CACHEPATH") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".arm");
        }

        public static bool GetDefaultVerbose()
        {
            return Environment.GetEnvironmentVariable("ARMCLIENT_VERBOSE") == "1";
        }

        public static string GetDefaultStamp()
        {
            return GetDefaultEnv() != AzureEnvironments.Dogfood ? null : Environment.GetEnvironmentVariable("ARMCLIENT_STAMP");
        }

        public static string GetDefaultStampCert()
        {
            return GetDefaultEnv() != AzureEnvironments.Dogfood ? null : Environment.GetEnvironmentVariable("ARMCLIENT_STAMPCERT");
        }

        public static void SetTraceListener(TraceListener listener)
        {
            _traceListener = listener;
        }

        public static string EnsureBase64Key(string key)
        {
            // assume already base64 if len > 16
            if (key.Length > 16)
            {
                return key;
            }

            // assume plain text password
            while (key.Length < 32)
            {
                key += key;
            }

            var bytes = Encoding.UTF8.GetBytes(key.Substring(0, 32));
            return Convert.ToBase64String(bytes);
        }

        class DefaultTraceListener : TraceListener
        {
            public readonly static TraceListener Default = new DefaultTraceListener();

            public override void Write(string message)
            {
                System.Diagnostics.Trace.Write(message);
            }

            public override void WriteLine(string message)
            {
                System.Diagnostics.Trace.WriteLine(message);
            }
        }

        public static async Task<int> HttpInvoke(Uri uri, TokenCacheInfo cacheInfo, string verb, DelegatingHandler handler, HttpContent content, Dictionary<string, List<string>> headers = null)
        {
            using (var client = new HttpClient(handler))
            {
                client.DefaultRequestHeaders.Add("User-Agent", Constants.UserAgent.Value, headers);
                client.DefaultRequestHeaders.Add("Accept", Constants.JsonContentType, headers);

                if (Utils.IsCustom(uri))
                {
                    if (Constants.CSMResources.Contains(cacheInfo.Resource))
                    {
                        var jwt = JsonConvert.DeserializeObject<JsonWebToken>(DecodeAccessToken(cacheInfo.AccessToken));

                        if (string.IsNullOrWhiteSpace(cacheInfo.DisplayableId))
                        {
                            client.DefaultRequestHeaders.Add("x-ms-principal-name", cacheInfo.DisplayableId);
                        }

                        client.DefaultRequestHeaders.Add("x-ms-client-tenant-id", cacheInfo.TenantId);
                        client.DefaultRequestHeaders.Add("x-ms-client-object-id", cacheInfo.ObjectId);
                        if (jwt.UniqueName != null)
                        {
                            client.DefaultRequestHeaders.Add("x-ms-client-principal-name", jwt.UniqueName);
                        }

                        var principalId = GetPrincipalId(jwt);
                        if (principalId != null)
                        {
                            client.DefaultRequestHeaders.Add("x-ms-client-principal-id", principalId);
                        }

                        if (headers != null && headers.ContainsKey("usertoken"))
                        {
                            client.DefaultRequestHeaders.Add("x-ms-arm-signed-user-token", headers["usertoken"]);
                            headers.Remove("usertoken");
                        }
                        else
                        {
                            client.DefaultRequestHeaders.Add("x-ms-arm-signed-user-token", cacheInfo.AccessToken);
                        }

                        client.DefaultRequestHeaders.Add("Referer", uri.OriginalString);
                    }
                    else
                    {
                        client.DefaultRequestHeaders.Add("Authorization", "Bearer " + cacheInfo.AccessToken);
                    }
                }
                else
                {
                    client.DefaultRequestHeaders.Add("Authorization", cacheInfo.CreateAuthorizationHeader(), headers);
                }

                if (Utils.IsRdfe(uri))
                {
                    client.DefaultRequestHeaders.Add("x-ms-version", "2013-10-01", headers);
                }

                if (Utils.IsCSM(uri))
                {
                    var stamp = GetDefaultStamp();
                    if (!String.IsNullOrEmpty(stamp))
                    {
                        client.DefaultRequestHeaders.Add("x-geoproxy-stamp", stamp, headers);
                    }

                    var stampCert = GetDefaultStampCert();
                    if (!String.IsNullOrEmpty(stampCert))
                    {
                        client.DefaultRequestHeaders.Add("x-geoproxy-stampcert", stampCert, headers);
                    }
                }

                var requestId = Guid.NewGuid().ToString();
                client.DefaultRequestHeaders.Add("x-ms-request-id", requestId);
                client.DefaultRequestHeaders.Add("x-ms-client-request-id", requestId);
                client.DefaultRequestHeaders.Add("x-ms-correlation-request-id", requestId);

                client.DefaultRequestHeaders.AddRemainingHeaders(headers);

                HttpResponseMessage response = null;
                if (String.Equals(verb, "get", StringComparison.OrdinalIgnoreCase))
                {
                    response = await client.GetAsync(uri);
                }
                else if (String.Equals(verb, "delete", StringComparison.OrdinalIgnoreCase))
                {
                    response = await client.DeleteAsync(uri);
                }
                else if (String.Equals(verb, "post", StringComparison.OrdinalIgnoreCase))
                {
                    response = await client.PostAsync(uri, content);
                }
                else if (String.Equals(verb, "put", StringComparison.OrdinalIgnoreCase))
                {
                    response = await client.PutAsync(uri, content);
                }
                else if (String.Equals(verb, "patch", StringComparison.OrdinalIgnoreCase))
                {
                    using (var message = new HttpRequestMessage(new HttpMethod("PATCH"), uri))
                    {
                        message.Content = content;
                        response = await client.SendAsync(message).ConfigureAwait(false);
                    }
                }
                else
                {
                    throw new InvalidOperationException(String.Format("Invalid http verb {0}!", verb));
                }

                using (response)
                {
                    if (response.IsSuccessStatusCode)
                    {
                        return 0;
                    }

                    return (-1) * (int)response.StatusCode;
                }
            }
        }

        public static string DecodeAccessToken(string accessToken)
        {
            var base64 = accessToken.Split('.')[1];

            // fixup
            int mod4 = base64.Length % 4;
            if (mod4 > 0)
            {
                base64 += new string('=', 4 - mod4);
            }

            return Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        }

        // PUsing PUIDs for Azure:
        // https://microsoft.sharepoint.com/:w:/t/azureresourcemanagerteam/Eafm5WMT0eRDvhaNJ3LNAssB6PCKAR0ON969Nq1qgQDcqA?e=9vVJfF
        private static string GetPrincipalId(JsonWebToken token)
        {
            string principalId = null;

            if (token.Idp == null || token.Idp == token.Iss)
            {
                // this is a single tenant case, use the Puid value
                principalId = token.Puid;
            }
            else
            {
                // this is a cross tenant case, parse and use the PUID from the AltSecId value
                if (!string.IsNullOrEmpty(token.AltSecId))
                {
                    const string LiveIdPrefix = "1:live.com:";
                    const string OrgIdPrefix = "5::";
                    if (token.AltSecId.StartsWith(LiveIdPrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        principalId = token.AltSecId.Substring(LiveIdPrefix.Length);
                    }
                    else if (token.AltSecId.StartsWith(OrgIdPrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        principalId = token.AltSecId.Substring(OrgIdPrefix.Length);
                    }
                }
            }

            if (principalId == null)
            {
                throw new NotSupportedException("Unsupported JSON Web Token values.");
            }

            return principalId;
        }

        public class JsonWebToken
        {
            public string Iss { get; set; }

            public string Idp { get; set; }

            public string AltSecId { get; set; }

            public string Puid { get; set; }

            [Newtonsoft.Json.JsonProperty("oid")]
            public string ObjectId { get; set; }

            [Newtonsoft.Json.JsonProperty("tid")]
            public string TenantId { get; set; }

            [Newtonsoft.Json.JsonProperty("unique_name")]
            public string UniqueName { get; set; }
        }

        private static void Add(this HttpRequestHeaders requestHeaders, string name, string value, Dictionary<string, List<string>> headers)
        {
            List<string> values;
            if (headers != null && headers.TryGetValue(name, out values))
            {
                requestHeaders.Add(name, values);
                headers.Remove(name);
            }
            else
            {
                requestHeaders.Add(name, value);
            }
        }

        private static void AddRemainingHeaders(this HttpRequestHeaders requestHeaders, Dictionary<string, List<string>> headers)
        {
            if (headers != null)
            {
                foreach (var pair in headers)
                {
                    requestHeaders.Add(pair.Key, pair.Value);
                }
                headers.Clear();
            }
        }

        public static async Task<JObject> HttpGet(Uri uri, TokenCacheInfo cacheInfo)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", cacheInfo.CreateAuthorizationHeader());
                client.DefaultRequestHeaders.Add("User-Agent", Constants.UserAgent.Value);
                client.DefaultRequestHeaders.Add("Accept", Constants.JsonContentType);

                if (Utils.IsRdfe(uri))
                {
                    client.DefaultRequestHeaders.Add("x-ms-version", "2013-10-01");
                }

                if (Utils.IsCSM(uri))
                {
                    var stamp = GetDefaultStamp();
                    if (!String.IsNullOrEmpty(stamp))
                    {
                        client.DefaultRequestHeaders.Add("x-geoproxy-stamp", stamp);
                    }

                    var stampCert = GetDefaultStampCert();
                    if (!String.IsNullOrEmpty(stampCert))
                    {
                        client.DefaultRequestHeaders.Add("x-geoproxy-stampcert", stampCert);
                    }
                }

                var requestId = Guid.NewGuid().ToString();
                client.DefaultRequestHeaders.Add("x-ms-request-id", requestId);
                client.DefaultRequestHeaders.Add("x-ms-client-request-id", requestId);
                client.DefaultRequestHeaders.Add("x-ms-correlation-request-id", requestId);

                using (var response = await client.GetAsync(uri))
                {
                    var content = await response.Content.ReadAsStringAsync();
                    if (!response.IsSuccessStatusCode)
                    {
                        Trace.WriteLine("Status:  " + response.StatusCode);
                        Trace.WriteLine("Content: " + content);
                    }

                    response.EnsureSuccessStatusCode();
                    return JObject.Parse(content);
                }
            }
        }

        public static Uri EnsureAbsoluteUri(string path, PersistentAuthHelper persistentAuthHelper)
        {
            Uri ret;
            if (Uri.TryCreate(path, UriKind.Absolute, out ret))
            {
                return ret;
            }

            var env = persistentAuthHelper.IsCacheValid() ? persistentAuthHelper.AzureEnvironments : AzureEnvironments.Prod;
            var parts = path.Split(new[] { '/', '?' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length <= 0
                || String.Equals(parts[0], "tenants", StringComparison.OrdinalIgnoreCase)
                || String.Equals(parts[0], "subscriptions", StringComparison.OrdinalIgnoreCase)
                || String.Equals(parts[0], "providers", StringComparison.OrdinalIgnoreCase))
            {
                return new Uri(new Uri(ARMClient.Authentication.Constants.CSMUrls[(int)env]), path);
            }

            Guid guid;
            if (Guid.TryParse(parts[0], out guid))
            {
                if (path.Length > 1 && String.Equals(parts[1], "services", StringComparison.OrdinalIgnoreCase))
                {
                    return new Uri(new Uri(ARMClient.Authentication.Constants.RdfeUrls[(int)env]), path);
                }
            }

            return new Uri(new Uri(ARMClient.Authentication.Constants.AADGraphUrls[(int)env]), path);
        }

        public static bool IsCustom(Uri uri)
        {
            return !IsRdfe(uri) && !IsCSM(uri) && !IsGraphApi(uri) && !IsKeyVault(uri);
        }

        public static bool IsRdfe(Uri uri)
        {
            var host = uri.Host;
            return Constants.RdfeUrls.Any(url => url.IndexOf(host, StringComparison.OrdinalIgnoreCase) > 0);
        }

        public static bool IsGraphApi(Uri uri)
        {
            var host = uri.Host;
            return Constants.AADGraphUrls.Any(url => url.IndexOf(host, StringComparison.OrdinalIgnoreCase) > 0);
        }

        public static bool IsCSM(Uri uri)
        {
            var host = uri.Host;
            return Constants.CSMUrls.Any(url => url.IndexOf(host, StringComparison.OrdinalIgnoreCase) > 0);
        }

        public static bool IsKeyVault(Uri uri)
        {
            var host = uri.Host;
            return host.EndsWith(".vault.azure.net", StringComparison.OrdinalIgnoreCase);
        }
    }
}
