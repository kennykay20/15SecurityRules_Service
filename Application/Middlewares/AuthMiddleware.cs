using _15SecurityRulesAPI.Application.Dtos.Response;
using _15SecurityRulesAPI.Infrastructure.Jwts;
using Serilog;
using System.Text.Json;


namespace _15SecurityRulesAPI.Application.Middlewares
{
    public class AuthMiddleware
    {
        private readonly RequestDelegate _requestDelegate;
        private readonly ILogger<AuthMiddleware> _logger;
        private readonly JwtService _jwtService;

        public AuthMiddleware(
            RequestDelegate requestDelegate,
            JwtService jwtService,
            ILogger<AuthMiddleware> logger
            )
        {
            this._requestDelegate = requestDelegate ?? throw new ArgumentNullException(nameof(requestDelegate));
            this._jwtService = jwtService ?? throw new ArgumentNullException(nameof(jwtService));
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                if (!context.Request.Headers.TryGetValue("authorization", out var tokenHeader))
                {
                    _logger.LogWarning("Missing 'userToken' header.");
                    await WriteJsonError(context, 400, "Missing 'userToken' header.");
                    return;
                }

                if (string.IsNullOrWhiteSpace(tokenHeader))
                {
                    _logger.LogWarning("Unauthorized client '{Client}'", tokenHeader.ToString());
                    await WriteJsonError(context, 401, "Unauthorized.");
                    return;
                }

                if (!string.IsNullOrEmpty(tokenHeader))
                {
                    var validateToken = await HandleTokenValidationAsync(context, tokenHeader!);
                    if (!validateToken)
                    {
                        await WriteJsonError(context, 401, "Unauthorized");
                        return;
                    }
                    await _requestDelegate(context);
                    return;
                }
            }
            catch (Exception ex)
            {
                Log.Fatal("An error occured", ex);
                Console.WriteLine($"An error occured {ex.Message}");
            }
        }

        private async Task<bool> HandleTokenValidationAsync(HttpContext context, string rawToken)
        {
            if (!rawToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return false;

            var token = rawToken.Substring("Bearer ".Length).Trim();

            var result = _jwtService.ValidateAndExtract(token);

            // await _cacheSvc.SetTokenAsync(category, identifier, result?.externalToken!);

            if (result != null && result?.email != null && result?.userName != null)
            {
                //await _cacheSvc.SetCacheAsync(category, identifier, result?.externalToken!);
                //context.Items["ExternalToken"] = result?.externalToken;
                context.Items["Email"] = result?.email;
                context.Items["UserName"] = result?.userName;
                return true;
            }

            return false;
        }

        private async Task WriteJsonError(HttpContext context, int statusCode, string message)
        {
            context.Response.StatusCode = statusCode;
            context.Response.ContentType = "application/json";

            var error = new ErrorResponse
            {
                responseCode = statusCode == 200 ? "00" : "99",
                responseMessage = message,
                responseData = null
            };

            var json = JsonSerializer.Serialize(error);
            await context.Response.WriteAsync(json);
        }
    }
}
