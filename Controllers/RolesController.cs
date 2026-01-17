using _15SecurityRulesAPI.Application.Dtos.Request;
using _15SecurityRulesAPI.Application.Dtos.Response;
using _15SecurityRulesAPI.Models.entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace _15SecurityRulesAPI.Controllers
{
    
    [ApiController]
    [Route("api/[controller]")]
    public class RolesController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<RolesController> _logger;
        

        public RolesController(
            RoleManager<IdentityRole> roleManager,
            UserManager<ApplicationUser> userManager,
            ILogger<RolesController> logger
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
        }

        // Create A NEW ROLE
        [HttpPost("create")]
        //[AllowAnonymous]
        [Authorize(Policy = "AdminOnly")] // Only admins can create roles
        public async Task<IActionResult> Create([FromBody] CreateRoleDto request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.RoleName))
                    return BadRequest(new { message = "Role name is required" });

                if (await _roleManager.RoleExistsAsync(request.RoleName))
                    return BadRequest(new { message = $"Role '{request.RoleName}' already exists" });

                var role = new IdentityRole(request.RoleName);
                var result = await _roleManager.CreateAsync(role);

                if (!result.Succeeded)
                    return BadRequest(new { errors = result.Errors });

                _logger.LogInformation("Role created: {RoleName}", request.RoleName);
                return Ok(new { message = $"Role '{request.RoleName}' created successfully", roleId = role.Id });
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occured in CreateRole request {ex}", ex);

                return StatusCode(500, new ProductAPIResponse<ProductDataDto>
                {
                    ResponseCode = "500",
                    ResponseMessage = "An error occurred. Try again later.",
                    ResponseData = null
                }); // HTTP 500
            }
        }

        // Get All Roles
        [HttpGet("getAll")]
        [Authorize(Policy = "AdminOnly")]
        public IActionResult GetAll()
        {
            try
            {
                //var claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();

                var roles = _roleManager.Roles
                    .Select(role => new { role.Id, role.Name })
                    .ToList();

                return Ok(roles);
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occured in Fetching Roles request {ex}", ex);

                return StatusCode(500, new ProductAPIResponse<string>
                {
                    ResponseCode = "500",
                    ResponseMessage = "An error occurred. Try again later.",
                    ResponseData = null
                }); // HTTP 500
            }
        }

        //Assign Role TO User
        [HttpPost("assign")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> AssignRoleToUser([FromBody] AssignRoleDto request)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                    return NotFound(new { message = "User not found" });

                if (!await _roleManager.RoleExistsAsync(request.RoleName))
                    return NotFound(new { message = $"Role '{request.RoleName}' does not exist" });

                if (await _userManager.IsInRoleAsync(user, request.RoleName))
                    return BadRequest(new { message = $"User already has role '{request.RoleName}'" });

                var result = await _userManager.AddToRoleAsync(user, request.RoleName);

                if (!result.Succeeded)
                    return BadRequest(new { errors = result.Errors });

                _logger.LogInformation("Role {RoleName} assigned to user {Email}", request.RoleName, request.Email);
                return Ok(new { message = $"Role '{request.RoleName}' assigned to {request.Email}" });
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occured in AssignRoleToUser request {ex}", ex);

                return StatusCode(500, new ProductAPIResponse<string>
                {
                    ResponseCode = "500",
                    ResponseMessage = "An error occurred. Try again later.",
                    ResponseData = null
                }); // HTTP 500
            }

        }

        // Remove Role from User
        [HttpPost("remove")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> RemoveRoleFromUser([FromBody] AssignRoleDto request)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                    return NotFound(new { message = "User not found" });

                if (!await _userManager.IsInRoleAsync(user, request.RoleName))
                    return BadRequest(new { message = $"User does not have role '{request.RoleName}'" });

                var result = await _userManager.RemoveFromRoleAsync(user, request.RoleName);

                if (!result.Succeeded)
                    return BadRequest(new { errors = result.Errors });

                _logger.LogInformation("Role {RoleName} removed from user {Email}", request.RoleName, request.Email);
                return Ok(new { message = $"Role '{request.RoleName}' removed from {request.Email}" });
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occured in RemoveRoleFromUser request {ex}", ex);

                return StatusCode(500, new ProductAPIResponse<string>
                {
                    ResponseCode = "500",
                    ResponseMessage = "An error occurred. Try again later.",
                    ResponseData = null
                }); // HTTP 500
            }
        }

        //Get User's Roles
        [HttpGet("user/{email}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> GetUserRoles(string email)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                    return NotFound(new { message = "User not found" });

                var roles = await _userManager.GetRolesAsync(user);

                return Ok(new { email = user.Email, roles });
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occured in Fetching UserRoles request {ex}", ex);

                return StatusCode(500, new ProductAPIResponse<string>
                {
                    ResponseCode = "500",
                    ResponseMessage = "An error occurred. Try again later.",
                    ResponseData = null
                }); // HTTP 500
            }
        }

    }
}
