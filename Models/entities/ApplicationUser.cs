using Microsoft.AspNetCore.Identity;

namespace _15SecurityRulesAPI.Models.entities
{
    public class ApplicationUser : IdentityUser
    {
        public DateTime DateOfBirth { get; set; }
    }
}
