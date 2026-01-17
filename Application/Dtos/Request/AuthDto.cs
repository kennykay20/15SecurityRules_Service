using System.ComponentModel.DataAnnotations;

namespace _15SecurityRulesAPI.Application.Dtos.Request
{
    public class AuthDto
    {
    }

    public class RegisterDto
    {
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        public string UserName { get; set; } = string.Empty;

        [Required]
        [StringLength(100, MinimumLength = 8)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$",
            ErrorMessage = "Password must contain uppercase, lowercase, number and special character")]
        public string Password { get; set; } = string.Empty;

        [Required]
        public DateTime DateOfBirth { get; set; }

        // ✅ OPTIONAL: Allow role assignment during registration
        public string? Role { get; set; } = "User"; // Defaults to "User" if not provided
    }

    public class LoginDto
    {
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        public string UserName { get; set; }

        [Required]
        public string Password { get; set; } = string.Empty;
    }
}
