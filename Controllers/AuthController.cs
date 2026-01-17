using _15SecurityRulesAPI.Application.Dtos.Request;
using _15SecurityRulesAPI.Application.Dtos.Response;
using _15SecurityRulesAPI.Application.Interfaces;
using _15SecurityRulesAPI.Models.entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace _15SecurityRulesAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _config;
        private readonly IAuthService _authSvc;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration config,
            IAuthService authSvc,
            RoleManager<IdentityRole> roleManager,
            ILogger<AuthController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _config = config;
            _authSvc = authSvc;
            _logger = logger;
            _roleManager = roleManager;
        }

        // Rule 5 & 15: Strong validation + password policies enforced by Identity
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterDto request)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                if(request.Email == null && request.UserName == null)
                    return BadRequest(new { errors = "Email and Username cannot be null"});

                var user = new ApplicationUser
                {
                    Email = request.Email,
                    UserName = request.UserName,
                    DateOfBirth = request.DateOfBirth
                };

                var response = await _userManager.CreateAsync(user, request.Password);
                if (!response.Succeeded)
                {
                    return BadRequest( new { errors = response.Errors });
                }

                // ✅ ASSIGN ROLE FROM PAYLOAD OR DEFAULT TO "User"
                string roleToAssign = !string.IsNullOrWhiteSpace(request.Role) &&
                                      await _roleManager.RoleExistsAsync(request.Role)
                                      ? request.Role
                                      : "User";

                await _userManager.AddToRoleAsync(user, roleToAssign);

                // Rule 10: Don't log passwords
                _logger.LogInformation("New user registered: {Email}, with role {Role}", request.Email, roleToAssign);

                return Ok(new { message = "Registration successful" });
            }
            catch(Exception ex)
            {
                _logger.LogError("An error occured in Register request {ex}", ex);

                return StatusCode(500, new AuthAPIResponse<string>
                {
                    ResponseCode = "500",
                    ResponseMessage = "An error occurred. Try again later.",
                    ResponseData = null
                }); // HTTP 500
            }
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginDto request)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                ApplicationUser user = null;
                if(!string.IsNullOrWhiteSpace(request.Email))
                {
                    var emailData = await _userManager.FindByEmailAsync(request.Email);
                    user = emailData!;
                }
                if (!string.IsNullOrEmpty(request.UserName))
                {
                    var userNameData = await _userManager.FindByNameAsync(request.UserName);
                    user = userNameData!;
                }

                if(user == null)
                {
                    // Rule 10: Don't reveal if email exists
                    _logger.LogWarning("Failed login attempt for {Email}", request.Email);
                    return Unauthorized(new { message = "Invalid credentials" });
                }

                var response = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

                if (response.IsLockedOut)
                {
                    _logger.LogWarning("User {Email} account locked out", request.Email);
                    return Unauthorized(new { message = "Account locked due to multiple failed login attempts" });
                }

                if (!response.Succeeded)
                {
                    _logger.LogInformation("Failed login for user {userId}", user.Id);
                    return Unauthorized(new { message = "Invalid credentials" });
                }

                var token = await _authSvc.GenerateJwtToken(user);

                // Rule 13: Secure cookie configuration
                Response.Cookies.Append("auth_token", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddHours(1)
                });

                _logger.LogInformation("User {userId} logged in successfully", user.Id);

                return Ok( new { Token = token, Email = user.Email, expiresIn = 3600 });
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occured in Register request {ex}", ex);

                return StatusCode(500, new AuthAPIResponse<string>
                {
                    ResponseCode = "500",
                    ResponseMessage = "An error occurred. Try again later.",
                    ResponseData = null
                }); // HTTP 500
            }
        }

        /// <summary>
        /// Validate if token is still valid (optional endpoint)
        /// </summary>
        [HttpGet("validate")]
        [Microsoft.AspNetCore.Authorization.Authorize]
        public IActionResult ValidateToken()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var email = User.FindFirstValue(ClaimTypes.Email);
            var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

            return Ok(new
            {
                valid = true,
                userId = userId,
                email = email,
                roles = roles
            });
        }
    }
}
