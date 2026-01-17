using Microsoft.AspNetCore.Authorization;

namespace _15SecurityRulesAPI.Application.Services
{
    public class MinimumAgeRequirement : IAuthorizationRequirement
    {
        public MinimumAgeRequirement(int age) => MinimumAge = age;

        public int MinimumAge { get; }
    }
}
