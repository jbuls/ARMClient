﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ARMClient.Authentication.Contracts;
using ARMClient.Authentication.EnvironmentStorage;
using ARMClient.Authentication.TenantStorage;
using ARMClient.Authentication.TokenStorage;
using ARMClient.Authentication.Utilities;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ARMClient.Authentication.AADAuthentication
{
    public abstract class BaseAuthHelper : IAuthHelper
    {
        protected readonly ITokenStorage TokenStorage;
        protected readonly ITenantStorage TenantStorage;
        protected readonly IEnvironmentStorage EnvironmentStorage;
        protected BaseAuthHelper(ITokenStorage tokenStorage,
            ITenantStorage tenantStorage, IEnvironmentStorage environmentStorage)
        {
            this.EnvironmentStorage = environmentStorage;
            this.TokenStorage = tokenStorage;
            this.TenantStorage = tenantStorage;
        }

        public AzureEnvironments AzureEnvironments
        {
            get { return this.EnvironmentStorage.GetSavedEnvironment(); }
            set { this.EnvironmentStorage.SaveEnvironment(value); }
        }

        public async Task AcquireTokens(string resource = null)
        {
            this.TokenStorage.ClearCache();
            this.TenantStorage.ClearCache();

            var tokenCache = new CustomTokenCache();
            var cacheInfo = await GetAuthorizationResult(tokenCache, Utils.GetLoginTenant(), user: null, resource: resource);
            Utils.Trace.WriteLine(string.Format("Welcome {0} (Tenant: {1})", cacheInfo.DisplayableId, cacheInfo.TenantId));

            var tenantCache = await GetTokenForTenants(tokenCache, cacheInfo);

            this.TokenStorage.SaveCache(tokenCache);
            this.TenantStorage.SaveCache(tenantCache);
        }

        public async Task AzLogin()
        {
            this.TokenStorage.ClearCache();
            this.TenantStorage.ClearCache();

            var tokens = GetAzLoginTokens();

            var tokenCache = new CustomTokenCache();
            var tenantCache = this.TenantStorage.GetCache();
            TokenCacheInfo recentInfo = null;
            foreach (var token in tokens)
            {
                var result = token.ToTokenCacheInfo();
                Guid unused;
                if (!Guid.TryParse(result.TenantId, out unused))
                {
                    continue;
                }

                tokenCache.Add(result);

                var tenantId = result.TenantId;
                var info = new TenantCacheInfo
                {
                    tenantId = tenantId,
                    displayName = "unknown",
                    domain = tenantId
                };

                Utils.Trace.WriteLine(string.Format("User: {0}, Tenant: {1}", result.DisplayableId, tenantId));
                try
                {
                    var subscriptions = await GetSubscriptions(result);
                    Utils.Trace.WriteLine(string.Format("\tThere are {0} subscriptions", subscriptions.Length));

                    info.subscriptions = subscriptions.Select(subscription => new SubscriptionCacheInfo
                    {
                        subscriptionId = subscription.subscriptionId,
                        displayName = subscription.displayName
                    }).ToArray();

                    if (recentInfo == null || info.subscriptions.Length > 0)
                    {
                        recentInfo = result;
                    }

                    foreach (var subscription in subscriptions)
                    {
                        Utils.Trace.WriteLine(string.Format("\tSubscription {0} ({1})", subscription.subscriptionId, subscription.displayName));
                    }
                }
                catch (Exception ex)
                {
                    Utils.Trace.WriteLine(string.Format("\t{0}!", ex.Message));
                }

                tenantCache[tenantId] = info;
                if (!String.IsNullOrEmpty(info.domain) && info.domain != "unknown")
                {
                    tenantCache[info.domain] = info;
                }

                Utils.Trace.WriteLine(string.Empty);
            }

            if (recentInfo != null)
            {
                this.TokenStorage.SaveRecentToken(recentInfo, Constants.CSMResources[(int)AzureEnvironments]);
            }

            this.TokenStorage.SaveCache(tokenCache);
            this.TenantStorage.SaveCache(tenantCache);
        }

        public async Task<TokenCacheInfo> GetTokenByResource(string resource)
        {
            var cacheInfo = await GetRecentToken(resource);
            if (cacheInfo != null)
            {
                return cacheInfo;
            }

            cacheInfo = await GetToken(null, null);
            var tokenCache = TokenStorage.GetCache();
            TokenCacheInfo found;
            if (tokenCache.TryGetValue(cacheInfo.TenantId, resource, out found))
            {
                cacheInfo = found;
            }
            else
            {
                cacheInfo = await GetAuthorizationResult(tokenCache, tenantId: cacheInfo.TenantId, user: cacheInfo.DisplayableId, resource: resource);
                this.TokenStorage.SaveCache(tokenCache);
            }

            this.TokenStorage.SaveRecentToken(cacheInfo, resource);
            return cacheInfo;
        }

        private AzAccessToken[] GetAzLoginTokens()
        {
            var azCmd = Environment.ExpandEnvironmentVariables(@"%ProgramFiles(x86)%\Microsoft SDKs\Azure\CLI2\wbin\az.cmd");
            if (!File.Exists(azCmd))
            {
                throw new InvalidOperationException("Azure cli is required.  Please download and install from https://aka.ms/InstallAzureCliWindows");
            }

            var accessTokensFile = Environment.ExpandEnvironmentVariables(@"%USERPROFILE%\.azure\accessTokens.json");
            var backupContent = File.Exists(accessTokensFile) ? File.ReadAllText(accessTokensFile) : null;
            try
            {
                if (File.Exists(accessTokensFile))
                {
                    File.Delete(accessTokensFile);
                }

                var processInfo = new ProcessStartInfo(azCmd, "login");
                processInfo.CreateNoWindow = true;
                processInfo.UseShellExecute = false;
                processInfo.RedirectStandardError = true;
                processInfo.RedirectStandardOutput = true;

                // start
                var process = Process.Start(processInfo);
                var processName = process.ProcessName;
                var processId = process.Id;

                // hook process event
                var processEvent = new ManualResetEvent(true);
                processEvent.SafeWaitHandle = new SafeWaitHandle(process.Handle, false);

                var hasOutput = false;
                var stdOutput = new StringBuilder();
                DataReceivedEventHandler stdHandler = (object sender, DataReceivedEventArgs e) =>
                {
                    if (e.Data != null)
                    {
                        if (!hasOutput)
                        {
                            Console.WriteLine();
                            hasOutput = true;
                        }

                        if (e.Data.IndexOf("[") >= 0 || stdOutput.Length > 0)
                        {
                            stdOutput.Append(e.Data);
                        }
                        else
                        {
                            Console.Write(e.Data);
                        }
                    }
                };

                // hoook stdout and stderr
                process.OutputDataReceived += stdHandler;
                process.BeginOutputReadLine();
                process.ErrorDataReceived += stdHandler;
                process.BeginErrorReadLine();

                // wait for ready
                Console.Write("Executing az login.");
                while (!processEvent.WaitOne(2000) && !hasOutput)
                {
                    Console.Write(".");
                }

                processEvent.WaitOne();
                if (process.ExitCode != 0)
                {
                    // if success, it contains the list of subscriptions
                    Console.WriteLine(stdOutput);

                    throw new InvalidOperationException("Process exit with " + process.ExitCode);
                }

                return JsonConvert.DeserializeObject<AzAccessToken[]>(File.ReadAllText(accessTokensFile));
            }
            finally
            {
                if (backupContent != null)
                {
                    File.WriteAllText(accessTokensFile, backupContent);
                }
                else
                {
                    File.Delete(accessTokensFile);
                }
            }
        }

        public async Task<TokenCacheInfo> GetToken(string id, string resource)
        {
            try
            {
                return await GetTokenInternal(id, resource);
            }
            catch (AdalServiceException ex)
            {
                if (ex.Message.IndexOf(" is expired") < 0)
                {
                    throw;
                }
            }

            await AcquireTokens();

            return await GetTokenInternal(id, resource);
        }

        private async Task<TokenCacheInfo> GetTokenInternal(string id, string resource)
        {
            if (String.IsNullOrEmpty(id))
            {
                return await GetRecentToken(resource ?? Constants.CSMResources[(int)AzureEnvironments]);
            }

            string tenantId = null;
            var tenantCache = this.TenantStorage.GetCache();
            TenantCacheInfo tenantInfo;
            if (tenantCache.TryGetValue(id, out tenantInfo))
            {
                id = tenantId = tenantInfo.tenantId;
            }

            if (String.IsNullOrEmpty(tenantId))
            {
                foreach (var tenant in tenantCache)
                {
                    if (tenant.Value.subscriptions.Any(s => s.subscriptionId == id))
                    {
                        tenantId = tenant.Key;
                        break;
                    }
                }
            }

            // look up tenant by assuming it is subscription
            if (String.IsNullOrEmpty(tenantId))
            {
                tenantId = await GetTenantIdFromSubscription(id, throwIfNotFound: true);
            }

            if (String.IsNullOrEmpty(tenantId))
            {
                return await GetRecentToken(Constants.CSMResources[(int)AzureEnvironments]);
            }

            if (string.IsNullOrEmpty(resource))
            {
                resource = id == tenantId ? Constants.AADGraphUrls[(int)AzureEnvironments] : Constants.CSMResources[(int)AzureEnvironments];
            }

            var tokenCache = this.TokenStorage.GetCache();
            TokenCacheInfo cacheInfo;
            if (!tokenCache.TryGetValue(tenantId, resource, out cacheInfo))
            {
                return await GetRecentToken(resource);
            }

            if (cacheInfo.ExpiresOn <= DateTimeOffset.UtcNow)
            {
                cacheInfo = await RefreshToken(tokenCache, cacheInfo);
                this.TokenStorage.SaveCache(tokenCache);
            }

            this.TokenStorage.SaveRecentToken(cacheInfo, resource);

            var armResource = Constants.CSMResources[(int)AzureEnvironments];
            if (resource != armResource)
            {
                TokenCacheInfo armInfo;
                if (tokenCache.TryGetValue(tenantId, armResource, out armInfo))
                {
                    this.TokenStorage.SaveRecentToken(armInfo, armResource);
                }
            }

            return cacheInfo;
        }

        private async Task<string> GetTenantIdFromSubscription(string subscriptionId, bool throwIfNotFound = true)
        {
            using (var client = new HttpClient())
            {
                var serviceUrl = ARMClient.Authentication.Constants.CSMUrls[(int)AzureEnvironments];
                string requestUri = String.Format("{0}/subscriptions/{1}?api-version=2014-04-01", serviceUrl.Trim('/'), subscriptionId);
                using (var response = await client.GetAsync(requestUri))
                {
                    if (response.StatusCode != HttpStatusCode.Unauthorized)
                    {
                        if (!throwIfNotFound && response.StatusCode == HttpStatusCode.NotFound)
                        {
                            return null;
                        }

                        throw new InvalidOperationException(String.Format("Expected Status {0} != {1} GET {2}", HttpStatusCode.Unauthorized, response.StatusCode, requestUri));
                    }

                    var header = response.Headers.WwwAuthenticate.SingleOrDefault();
                    if (header == null || String.IsNullOrEmpty(header.Parameter))
                    {
                        throw new InvalidOperationException(String.Format("Missing WWW-Authenticate response header GET {0}", requestUri));
                    }

                    // WWW-Authenticate: Bearer authorization_uri="https://login.windows.net/<tenantid>", error="invalid_token", error_description="The access token is missing or invalid."
                    var index = header.Parameter.IndexOf("authorization_uri=", StringComparison.OrdinalIgnoreCase);
                    if (index < 0)
                    {
                        throw new InvalidOperationException(String.Format("Invalid WWW-Authenticat response header {0} GET {1}", header.Parameter, requestUri));
                    }

                    var parts = header.Parameter.Substring(index).Split(new[] { '\"', '=' }, StringSplitOptions.RemoveEmptyEntries);
                    return new Uri(parts[1]).AbsolutePath.Trim('/');
                }
            }
        }

        public async Task<TokenCacheInfo> GetTokenBySpn(string tenantId, string appId, string appKey, string resource = null)
        {
            this.TokenStorage.ClearCache();
            this.TenantStorage.ClearCache();

            var tokenCache = new CustomTokenCache();
            var cacheInfo = GetAuthorizationResultBySpn(tokenCache, tenantId, appId, appKey, resource ?? Constants.CSMResources[(int)AzureEnvironments]);

            var tenantCache = await GetTokenForTenants(tokenCache, cacheInfo, appId, appKey, resource);

            this.TokenStorage.SaveCache(tokenCache);
            this.TenantStorage.SaveCache(tenantCache);

            return cacheInfo;
        }

        public async Task<TokenCacheInfo> GetTokenBySpn(string tenantId, string appId, X509Certificate2 certificate, string resource = null)
        {
            this.TokenStorage.ClearCache();
            this.TenantStorage.ClearCache();

            var tokenCache = new CustomTokenCache();
            var cacheInfo = await GetAuthorizationResultBySpn(tokenCache, tenantId, appId, certificate, resource ?? Constants.CSMResources[(int)AzureEnvironments]);

            var tenantCache = await GetTokenForTenants(tokenCache, cacheInfo, appId, appKey: "_certificate_", resource: resource);

            this.TokenStorage.SaveCache(tokenCache);
            this.TenantStorage.SaveCache(tenantCache);

            return cacheInfo;
        }

        public async Task<TokenCacheInfo> GetTokenByUpn(string username, string password)
        {
            this.TokenStorage.ClearCache();
            this.TenantStorage.ClearCache();

            var tokenCache = new CustomTokenCache();
            var cacheInfo = GetAuthorizationResultByUpn(tokenCache, "common", username, password, Constants.CSMResources[(int)AzureEnvironments]);

            var tenantCache = await GetTokenForTenants(tokenCache, cacheInfo, username: username, password: password);

            this.TokenStorage.SaveCache(tokenCache);
            this.TenantStorage.SaveCache(tenantCache);

            return cacheInfo;
        }

        protected async Task<TokenCacheInfo> GetRecentToken(string resource)
        {
            TokenCacheInfo cacheInfo = this.TokenStorage.GetRecentToken(resource);
            if (cacheInfo != null && cacheInfo.ExpiresOn <= DateTimeOffset.UtcNow)
            {
                var tokenCache = this.TokenStorage.GetCache();
                cacheInfo = await RefreshToken(tokenCache, cacheInfo);
                this.TokenStorage.SaveCache(tokenCache);
                this.TokenStorage.SaveRecentToken(cacheInfo, resource);
            }

            return cacheInfo;
        }

        protected async Task<TokenCacheInfo> RefreshToken(CustomTokenCache tokenCache, TokenCacheInfo cacheInfo)
        {
            if (!String.IsNullOrEmpty(cacheInfo.RefreshToken))
            {
                return await GetAuthorizationResultByRefreshToken(tokenCache, cacheInfo);
            }
            else if (!String.IsNullOrEmpty(cacheInfo.AppId) && cacheInfo.AppKey == "_certificate_")
            {
                throw new InvalidOperationException("Unable to refresh expired token!  Try login with certificate again.");
            }
            else if (!String.IsNullOrEmpty(cacheInfo.AppId) && !String.IsNullOrEmpty(cacheInfo.AppKey))
            {
                return GetAuthorizationResultBySpn(tokenCache, cacheInfo.TenantId, cacheInfo.AppId, cacheInfo.AppKey, cacheInfo.Resource);
            }

            throw new NotImplementedException();
        }

        public bool IsCacheValid()
        {
            return this.EnvironmentStorage.IsCacheValid() && this.TokenStorage.IsCacheValid() && this.TenantStorage.IsCacheValid();
        }

        public void ClearTokenCache()
        {
            this.TokenStorage.ClearCache();
            this.TenantStorage.ClearCache();
            this.EnvironmentStorage.ClearSavedEnvironment();
        }

        public IEnumerable<string> DumpTokenCache()
        {
            var tokenCache = this.TokenStorage.GetCache();
            var tenantCache = this.TenantStorage.GetCache();
            foreach (var cacheItem in tokenCache.GetValues(Constants.CSMResources[(int)AzureEnvironments]))
            {
                var tenantId = cacheItem.TenantId;
                var details = tenantCache[tenantId];
                if (!String.IsNullOrEmpty(cacheItem.DisplayableId))
                {
                    yield return string.Format("User: {0}, Tenant: {1} ({2})", cacheItem.DisplayableId, tenantId, details.domain);
                }
                else if (!String.IsNullOrEmpty(cacheItem.AppId))
                {
                    yield return string.Format(String.IsNullOrEmpty(details.domain) ? "App: {0}, Tenant: {1}" : "App: {0}, Tenant: {1} ({2})", cacheItem.AppId, tenantId, details.domain);
                }
                else
                {
                    throw new NotImplementedException();
                }

                var subscriptions = details.subscriptions;
                yield return string.Format("\tThere are {0} subscriptions", subscriptions.Length);

                foreach (var subscription in subscriptions)
                {
                    yield return string.Format("\tSubscription {0} ({1})", subscription.subscriptionId, subscription.displayName);
                }
                yield return string.Empty;
            }
        }

        protected async Task<TokenCacheInfo> GetAuthorizationResultByRefreshToken(CustomTokenCache tokenCache, TokenCacheInfo cacheInfo)
        {
            var azureEnvironment = this.AzureEnvironments;
            var authority = String.Format("{0}/{1}", Constants.AADLoginUrls[(int)azureEnvironment], cacheInfo.TenantId);
            var context = new AuthenticationContext(
                authority: authority,
                validateAuthority: true,
                tokenCache: tokenCache);

            AuthenticationResult result = await context.AcquireTokenByRefreshTokenAsync(
                    refreshToken: cacheInfo.RefreshToken,
                    clientId: !string.IsNullOrEmpty(cacheInfo.ClientId) ? cacheInfo.ClientId : Constants.AADClientId,
                    resource: cacheInfo.Resource);

            var ret = new TokenCacheInfo(cacheInfo.Resource, result);
            ret.TenantId = cacheInfo.TenantId;
            ret.DisplayableId = cacheInfo.DisplayableId;
            ret.ClientId = cacheInfo.ClientId;
            tokenCache.Add(ret);
            return ret;
        }

        protected Task<TokenCacheInfo> GetAuthorizationResult(CustomTokenCache tokenCache, string tenantId, string user = null, string resource = null)
        {
            var tcs = new TaskCompletionSource<TokenCacheInfo>();

            resource = resource ?? Constants.CSMResources[(int)AzureEnvironments];

            TokenCacheInfo found;
            if (tokenCache.TryGetValue(tenantId, resource, out found))
            {
                tcs.SetResult(found);
                return tcs.Task;
            }

            var thread = new Thread(() =>
            {
                try
                {
                    var azureEnvironment = this.AzureEnvironments;
                    var authority = String.Format("{0}/{1}", Constants.AADLoginUrls[(int)azureEnvironment], tenantId);
                    var context = new AuthenticationContext(
                        authority: authority,
                        validateAuthority: true,
                        tokenCache: tokenCache);

                    AuthenticationResult result = null;
                    if (!string.IsNullOrEmpty(user))
                    {
                        try
                        {
                            result = context.AcquireToken(
                                resource: resource,
                                clientId: Constants.AADClientId,
                                redirectUri: new Uri(Constants.AADRedirectUri),
                                promptBehavior: PromptBehavior.Never,
                                userId: new UserIdentifier(user, UserIdentifierType.OptionalDisplayableId));
                        }
                        catch (AdalException adalEx)
                        {
                            if (adalEx.Message.IndexOf("user_interaction_required") < 0)
                            {
                                throw;
                            }

                            result = context.AcquireToken(
                                resource: resource,
                                clientId: Constants.AADClientId,
                                redirectUri: new Uri(Constants.AADRedirectUri),
                                promptBehavior: PromptBehavior.Auto,
                                userId: new UserIdentifier(user, UserIdentifierType.OptionalDisplayableId));
                        }
                    }
                    else
                    {
                        result = context.AcquireToken(
                            resource: resource,
                            clientId: Constants.AADClientId,
                            redirectUri: new Uri(Constants.AADRedirectUri),
                            promptBehavior: PromptBehavior.Always);
                    }

                    var cacheInfo = new TokenCacheInfo(resource, result)
                    {
                        ObjectId = result.UserInfo.UniqueId
                    };
                    tokenCache.Add(cacheInfo);
                    tcs.TrySetResult(cacheInfo);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            });

            thread.SetApartmentState(ApartmentState.STA);
            thread.Name = "AcquireTokenThread";
            thread.Start();

            return tcs.Task;
        }

        protected TokenCacheInfo GetAuthorizationResultBySpn(CustomTokenCache tokenCache, string tenantId, string appId, string appKey, string resource)
        {
            TokenCacheInfo found;
            if (tokenCache.TryGetValue(tenantId, resource, out found))
            {
                return found;
            }

            var azureEnvironment = this.AzureEnvironments;
            var authority = String.Format("{0}/{1}", Constants.AADLoginUrls[(int)azureEnvironment], tenantId);
            var context = new AuthenticationContext(
                authority: authority,
                validateAuthority: true,
                tokenCache: tokenCache);
            var credential = new ClientCredential(appId, appKey);
            var result = context.AcquireToken(resource, credential);

            var cacheInfo = new TokenCacheInfo(tenantId, appId, appKey, resource, result);
            tokenCache.Add(cacheInfo);
            return cacheInfo;
        }

        protected async Task<TokenCacheInfo> GetAuthorizationResultBySpn(CustomTokenCache tokenCache, string tenantId, string appId, X509Certificate2 certificate, string resource)
        {
            TokenCacheInfo found;
            if (tokenCache.TryGetValue(tenantId, resource, out found))
            {
                return found;
            }

            var helper = new JwtHelper();
            var tokenEndpoint = string.Format("{0}/{1}/oauth2/token", Constants.AADLoginUrls[(int)this.AzureEnvironments], tenantId);
            var token = await helper.AcquireTokenByX509(tenantId, appId, certificate, resource, tokenEndpoint);

            var cacheInfo = new TokenCacheInfo(tenantId, appId, "_certificate_", resource, token);
            tokenCache.Add(cacheInfo);
            return cacheInfo;
        }

        protected TokenCacheInfo GetAuthorizationResultByUpn(CustomTokenCache tokenCache, string tenantId, string username, string password, string resource)
        {
            TokenCacheInfo found;
            if (tokenCache.TryGetValue(tenantId, resource, out found))
            {
                return found;
            }

            var azureEnvironment = this.AzureEnvironments;
            var authority = String.Format("{0}/{1}", Constants.AADLoginUrls[(int)azureEnvironment], tenantId);
            var context = new AuthenticationContext(
                authority: authority,
                validateAuthority: true,
                tokenCache: tokenCache);
            var credential = new UserCredential(username, password);
            var result = context.AcquireToken(resource, Constants.AADClientId, credential);

            var cacheInfo = new TokenCacheInfo(resource, result);
            tokenCache.Add(cacheInfo);
            return cacheInfo;
        }

        protected async Task<Dictionary<string, TenantCacheInfo>> GetTokenForTenants(CustomTokenCache tokenCache, TokenCacheInfo cacheInfo,
            string appId = null, string appKey = null, string username = null, string password = null, string resource = null)
        {
            var recentInfo = cacheInfo;
            var tenantIds = resource == null
                ? await GetTenantIds(cacheInfo)
                : new string[] { cacheInfo.TenantId };
            if (!tenantIds.Contains(cacheInfo.TenantId))
            {
                var list = tenantIds.ToList();
                list.Insert(0, cacheInfo.TenantId);
                tenantIds = list.ToArray();
            }

            var tenantCache = this.TenantStorage.GetCache();
            foreach (var tenantId in tenantIds)
            {
                var info = new TenantCacheInfo
                {
                    tenantId = tenantId,
                    displayName = "unknown",
                    domain = tenantId
                };

                TokenCacheInfo result = null;
                try
                {
                    if (!String.IsNullOrEmpty(appId) && !String.IsNullOrEmpty(appKey))
                    {
                        result = GetAuthorizationResultBySpn(tokenCache, tenantId: tenantId, appId: appId, appKey: appKey, resource: resource ?? Constants.CSMResources[(int)AzureEnvironments]);
                    }
                    else if (!String.IsNullOrEmpty(username) && !String.IsNullOrEmpty(password))
                    {
                        result = GetAuthorizationResultByUpn(tokenCache, tenantId: tenantId, username: username, password: password, resource: resource ?? Constants.CSMResources[(int)AzureEnvironments]);
                    }
                    else
                    {
                        result = await GetAuthorizationResult(tokenCache, tenantId: tenantId, user: cacheInfo.DisplayableId, resource: resource);
                    }
                }
                catch (Exception ex)
                {
                    Utils.Trace.WriteLine(string.Format("User: {0}, Tenant: {1} {2}", cacheInfo.DisplayableId, tenantId, ex.Message));
                    Utils.Trace.WriteLine(string.Empty);
                    continue;
                }

                try
                {
                    TokenCacheInfo aadToken = null;
                    if (!String.IsNullOrEmpty(appId) && appKey == "_certificate_")
                    {
                        Utils.Trace.WriteLine(string.Format("AppId: {0}, Tenant: {1}", appId, tenantId));
                    }
                    else if (!String.IsNullOrEmpty(appId) && !String.IsNullOrEmpty(appKey))
                    {
                        aadToken = GetAuthorizationResultBySpn(tokenCache, tenantId: tenantId, appId: appId, appKey: appKey, resource: resource ?? Constants.AADGraphUrls[(int)AzureEnvironments]);
                    }
                    else if (!String.IsNullOrEmpty(username) && !String.IsNullOrEmpty(password))
                    {
                        aadToken = GetAuthorizationResultByUpn(tokenCache, tenantId: tenantId, username: username, password: password, resource: resource ?? Constants.AADGraphUrls[(int)AzureEnvironments]);
                    }
                    else
                    {
                        aadToken = await GetAuthorizationResult(tokenCache, tenantId: tenantId, user: cacheInfo.DisplayableId, resource: resource ?? Constants.AADGraphUrls[(int)AzureEnvironments]);
                    }

                    if (aadToken != null)
                    {
                        var details = await GetTenantDetail(aadToken, tenantId);
                        info.displayName = details.displayName;
                        info.domain = details.verifiedDomains.First(d => d.@default).name;

                        if (!String.IsNullOrEmpty(appId) && !String.IsNullOrEmpty(appKey))
                        {
                            Utils.Trace.WriteLine(string.Format("AppId: {0}, Tenant: {1} ({2})", appId, tenantId, info.domain));
                        }
                        else
                        {
                            Utils.Trace.WriteLine(string.Format("User: {0}, Tenant: {1} ({2})", result.DisplayableId, tenantId, info.domain));
                        }
                    }
                }
                catch (Exception)
                {
                    if (!String.IsNullOrEmpty(appId) && !String.IsNullOrEmpty(appKey))
                    {
                        Utils.Trace.WriteLine(string.Format("AppId: {0}, Tenant: {1}", appId, tenantId));
                    }
                    else
                    {
                        Utils.Trace.WriteLine(string.Format("User: {0}, Tenant: {1}", result.DisplayableId, tenantId));
                    }
                }

                try
                {
                    if (Constants.CSMResources[(int)AzureEnvironments] == result.Resource)
                    {
                        var subscriptions = await GetSubscriptions(result);
                        Utils.Trace.WriteLine(string.Format("\tThere are {0} subscriptions", subscriptions.Length));

                        info.subscriptions = subscriptions.Select(subscription => new SubscriptionCacheInfo
                        {
                            subscriptionId = subscription.subscriptionId,
                            displayName = subscription.displayName
                        }).ToArray();

                        if (recentInfo != null && info.subscriptions.Length > 0)
                        {
                            recentInfo = result;
                        }

                        foreach (var subscription in subscriptions)
                        {
                            Utils.Trace.WriteLine(string.Format("\tSubscription {0} ({1})", subscription.subscriptionId, subscription.displayName));
                        }
                    }
                }
                catch (Exception ex)
                {
                    Utils.Trace.WriteLine(string.Format("\t{0}!", ex.Message));
                }

                tenantCache[tenantId] = info;
                if (!String.IsNullOrEmpty(info.domain) && info.domain != "unknown")
                {
                    tenantCache[info.domain] = info;
                }

                Utils.Trace.WriteLine(string.Empty);
            }

            this.TokenStorage.SaveRecentToken(recentInfo, resource ?? Constants.CSMResources[(int)AzureEnvironments]);

            return tenantCache;
        }

        private async Task<string[]> GetTenantIds(TokenCacheInfo cacheInfo)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", cacheInfo.CreateAuthorizationHeader());
                client.DefaultRequestHeaders.Add("User-Agent", Constants.UserAgent.Value);

                var azureEnvironment = this.AzureEnvironments;
                var url = string.Format("{0}/tenants?api-version={1}", Constants.CSMUrls[(int)azureEnvironment], Constants.CSMApiVersion);
                using (var response = await client.GetAsync(url))
                {
                    if (response.IsSuccessStatusCode)
                    {
                        var result = await response.Content.ReadAsAsync<ResultOf<TenantInfo>>();
                        return result.value.Select(tenant => tenant.tenantId).ToArray();
                    }

                    throw new InvalidOperationException(await response.Content.ReadAsStringAsync());
                }
            }
        }

        private async Task<TenantDetails> GetTenantDetail(TokenCacheInfo cacheInfo, string tenantId)
        {
            if (Constants.InfrastructureTenantIds.Contains(tenantId))
            {
                return new TenantDetails
                {
                    objectId = tenantId,
                    displayName = "Infrastructure",
                    verifiedDomains = new[]
                    {
                        new VerifiedDomain
                        {
                            name = "live.com",
                            @default = true
                        }
                    }
                };
            }

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", cacheInfo.CreateAuthorizationHeader());
                client.DefaultRequestHeaders.Add("User-Agent", Constants.UserAgent.Value);

                var azureEnvironment = this.AzureEnvironments;
                var url = string.Format("{0}/{1}/tenantDetails?api-version={2}", Constants.AADGraphUrls[(int)azureEnvironment], tenantId, Constants.AADGraphApiVersion);
                using (var response = await client.GetAsync(url))
                {
                    if (response.IsSuccessStatusCode)
                    {
                        var result = await response.Content.ReadAsAsync<ResultOf<TenantDetails>>();
                        return result.value[0];
                    }

                    var content = await response.Content.ReadAsStringAsync();
                    if (content.StartsWith("{"))
                    {
                        var error = (JObject)JObject.Parse(content)["odata.error"];
                        if (error != null)
                        {
                            throw new InvalidOperationException(String.Format("GetTenantDetail {0}, {1}", response.StatusCode, error["message"].Value<string>("value")));
                        }
                    }

                    throw new InvalidOperationException(String.Format("GetTenantDetail {0}, {1}", response.StatusCode, await response.Content.ReadAsStringAsync()));
                }
            }
        }

        private async Task<SubscriptionInfo[]> GetSubscriptions(TokenCacheInfo cacheInfo)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", cacheInfo.CreateAuthorizationHeader());
                client.DefaultRequestHeaders.Add("User-Agent", Constants.UserAgent.Value);

                var azureEnvironment = this.AzureEnvironments;
                var url = string.Format("{0}/subscriptions?api-version={1}", Constants.CSMUrls[(int)azureEnvironment], Constants.CSMApiVersion);
                using (var response = await client.GetAsync(url))
                {
                    if (response.IsSuccessStatusCode)
                    {
                        var result = await response.Content.ReadAsAsync<ResultOf<SubscriptionInfo>>();
                        return result.value;
                    }

                    var content = await response.Content.ReadAsStringAsync();
                    if (content.StartsWith("{"))
                    {
                        var error = (JObject)JObject.Parse(content)["error"];
                        if (error != null)
                        {
                            throw new InvalidOperationException(String.Format("GetSubscriptions {0}, {1}", response.StatusCode, error.Value<string>("message")));
                        }
                    }

                    throw new InvalidOperationException(String.Format("GetSubscriptions {0}, {1}", response.StatusCode, await response.Content.ReadAsStringAsync()));
                }
            }
        }

    }
}
