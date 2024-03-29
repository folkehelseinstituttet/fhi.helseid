﻿using Fhi.HelseId.Common;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace Fhi.HelseId.Api.Handlers
{
    public class NoAuthorizationHandler : AuthorizationHandler<NoAuthorizationRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, NoAuthorizationRequirement requirement)
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }
}
