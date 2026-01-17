using System.ComponentModel.DataAnnotations;

namespace _15SecurityRulesAPI.Application.Dtos.Request
{
    public class CreateRoleDto
    {
        [Required]
        [StringLength(50, MinimumLength = 2)]
        public string RoleName { get; set; }
        public string Description { get; set; }
    }

    public class AssignRoleDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string RoleName { get; set; }
    }
}
