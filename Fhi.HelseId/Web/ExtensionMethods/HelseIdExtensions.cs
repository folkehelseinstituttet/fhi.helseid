using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Fhi.HelseId.Common;
using Fhi.HelseId.Common.Identity;
using Fhi.HelseId.Web.Infrastructure.AutomaticTokenManagement;
using Fhi.HelseId.Web.Services;
using IdentityModel;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Fhi.HelseId.Web.ExtensionMethods
{
    public static class HelseIdExtensions
    {
        public static void DefaultHelseIdOptions(this CookieAuthenticationOptions options, 
            IHelseIdWebKonfigurasjon configAuth, 
            IRedirectPagesKonfigurasjon redirectPagesKonfigurasjon)
        {
            options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
            options.SlidingExpiration = true;
            options.Cookie.HttpOnly = true;
            options.Cookie.IsEssential = true;
            options.Cookie.SecurePolicy = configAuth.UseHttps ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
            options.AccessDeniedPath = redirectPagesKonfigurasjon.Forbidden;
            // NOTE: options.Events must be set in AddAutomaticTokenManagement.
            // This is because it overrides the events set here.
        }

        public static void DefaultHelseIdOptions(this OpenIdConnectOptions options, 
            IHelseIdWebKonfigurasjon configAuth, 
            IRedirectPagesKonfigurasjon redirectPagesKonfigurasjon, 
            IHelseIdSecretHandler secretHandler)
        {
            var acrValues = GetAcrValues(configAuth); // spesielt for id-porten, e.g. krever sikkerhetsnivå 4
            var hasAcrValues = !string.IsNullOrWhiteSpace(acrValues);
            options.Authority = configAuth.Authority;
            options.RequireHttpsMetadata = true;
            options.ClientId = configAuth.ClientId;

            options.ResponseType = "code";
            options.TokenValidationParameters.ValidAudience = configAuth.ClientId;
            options.CallbackPath = "/signin-callback";
            options.SignedOutCallbackPath = "/signout-callback";
            options.Scope.Clear();
            //options.CorrelationCookie.SameSite = SameSiteMode.Lax;
            //options.NonceCookie.SameSite = SameSiteMode.Lax;
            foreach (var scope in configAuth.AllScopes)
            {
                options.Scope.Add(scope.Trim());
            }
            options.SaveTokens = true;
            options.Events.OnRedirectToIdentityProvider = ctx =>
            {
                //API requests should get a 401 status instead of being redirected to login
                if (ctx.Request.Path.StartsWithSegments("/api"))
                {
                    ctx.Response.Headers["Location"] = ctx.ProtocolMessage.CreateAuthenticationRequestUrl();
                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    ctx.HandleResponse();
                }

                if (ctx.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication && hasAcrValues)
                {
                    ctx.ProtocolMessage.AcrValues = acrValues;
                }

                return Task.CompletedTask;
            };

            options.AccessDeniedPath = redirectPagesKonfigurasjon.Forbidden;    

            secretHandler.AddSecretConfiguration(configAuth as IHelseIdClientKonfigurasjon, options);

            string GetAcrValues(IHelseIdWebKonfigurasjon helseIdWebKonfigurasjon)
            {
                return string.Join(' ',helseIdWebKonfigurasjon.SecurityLevels.Select(sl => $"Level{sl}"));
            }
        }


        /// <summary>
        /// Setter default helse-id opsjoner for automatisk token management,parameter for refresh tid i minutter
        /// </summary>
        /// <param name="options"></param>
        /// <param name="refreshBeforeExpirationTime">Tid i minutter</param>
        public static void DefaultHelseIdOptions(this AutomaticTokenManagementOptions options,double refreshBeforeExpirationTime)
        {
            options.RefreshBeforeExpiration = TimeSpan.FromMinutes(refreshBeforeExpirationTime);
            options.RevokeRefreshTokenOnSignout = true;
            options.Scheme = HelseIdContext.Scheme; 

            options.CookieEvents.OnRedirectToAccessDenied = ctx =>
            {
                // API requests should get a 403 status instead of being redirected to access denied page
                if (ctx.Request.Path.StartsWithSegments("/api"))
                {
                    ctx.Response.Headers["Location"] = ctx.RedirectUri;
                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                }

                return Task.CompletedTask;
            };
        }
    }
}
