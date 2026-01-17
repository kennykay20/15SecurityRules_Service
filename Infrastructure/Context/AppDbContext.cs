using _15SecurityRulesAPI.Models.entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace _15SecurityRulesAPI.Infrastructure.Context
{
    public class AppDbContext : IdentityDbContext<ApplicationUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) 
        {
        }
        public DbSet<Product> Products { get; set; }
        //public DbSet<UserRole> UserRoles { get; set; }
    }
}
