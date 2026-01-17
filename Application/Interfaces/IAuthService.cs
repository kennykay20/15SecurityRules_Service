using _15SecurityRulesAPI.Models.entities;

namespace _15SecurityRulesAPI.Application.Interfaces
{
    public interface IAuthService
    {
        Task<string> GenerateJwtToken(ApplicationUser user);
    }
}
