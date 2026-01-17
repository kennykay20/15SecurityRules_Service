using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace _15SecurityRulesAPI.Infrastructure.Jwts
{
    public class JwtService
    {
        private readonly JwtSettings _jwtSetting;
        private readonly ILogger<JwtService> _logger;
        public JwtService(IOptions<JwtSettings> options, ILogger<JwtService> logger)
        {
            _jwtSetting = options.Value;
            _logger = logger;
        }
        public (string email, string userName)? ValidateAndExtract(string jwtToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSetting.SecretKey);
            _logger.LogInformation("key: {key}", key);

            try
            {
                var principal = tokenHandler.ValidateToken(jwtToken, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = _jwtSetting.Issuer,
                    ValidAudience = _jwtSetting.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ClockSkew = TimeSpan.Zero
                }, out _);
                Console.WriteLine($"principals = {principal}");
                var email = principal.FindFirst(ClaimTypes.Email)?.Value;
                var userName = principal.FindFirst(ClaimTypes.Name)?.Value;
                

                return (email!, userName!);
            }
            catch (Exception ex)
            {
                return null;
            }
        }
    }
}
