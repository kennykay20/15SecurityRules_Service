using _15SecurityRulesAPI.Application.Interfaces;
using _15SecurityRulesAPI.Application.Middlewares;
using _15SecurityRulesAPI.Application.Services;
using _15SecurityRulesAPI.Helper;
using _15SecurityRulesAPI.Infrastructure.Context;
using _15SecurityRulesAPI.Infrastructure.Jwts;
using _15SecurityRulesAPI.Infrastructure.Repository.Interfaces;
using _15SecurityRulesAPI.Infrastructure.Repository.Services;
using _15SecurityRulesAPI.Models.entities;
using AspNetCoreRateLimit;
//using AspNetCore.RateLimit;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var applicationName = "SecurityRules Service";

// 1️ Bootstrap Serilog first — before creating builder
Log.Logger = new LoggerConfiguration()
    .Enrich.FromLogContext()
    .Enrich.WithProperty("ApplicationName", applicationName)
    .Enrich.WithMachineName()
    .Enrich.WithThreadId()
    .Enrich.With<NigeriaTimeEnricher>()
    .WriteTo.Console(outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] (NGA: {NigeriaTime}) ({ApplicationName}) {Message:lj}{NewLine}{Exception}")
    .CreateBootstrapLogger();

Log.Information("Starting {ApplicationName} bootstrap logger...", applicationName);

var builder = WebApplication.CreateBuilder(args);



builder.Host.UseSerilog((context, services, loggerConfiguration) =>
{
    loggerConfiguration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.WithProperty("ApplicationName", applicationName)
        .Enrich.FromLogContext()
        .Enrich.With<NigeriaTimeEnricher>()
        .WriteTo.Console( // fallback if config load fails
            outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}"
        );
}); // Full Serilog integration

// Add services to the container.


builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Product Service API",
        Version = "v1",
        Description = "Documentation of the Product Service API",
        Contact = new OpenApiContact { Name = "Dev Team", Email = "support@h.com" }
    });

    // Enable XML comments for better documentation
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    //options.IncludeXmlComments(xmlPath);

    // JWT Bearer Authentication (if needed)
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Enter JWT Bearer token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Database context
//builder.Services.AddDbContext<AppDbContext>(options => options.UseInMemoryDatabase("RulesOfDataDb"));
builder.Services.AddDbContext<AppDbContext>(
   option => option.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Repositories
builder.Services.AddScoped<IProductRecordRepository, ProductRecordRepository>();

// services
builder.Services.AddScoped<IProductService, ProductService>();
builder.Services.AddScoped<IAuthService, AuthService>();
//builder.Services.AddSingleton<JwtService>();

// Rule 15: Strong password policies with Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 8;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(15);
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

// Rule 2 & 3; JWT Authentication with validation
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT Secret not configured");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
        ClockSkew = TimeSpan.Zero,
        RoleClaimType = ClaimTypes.Role
    };

    // Add event handlers to debug
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            Console.WriteLine($"RAW Authorization header: {authHeader}");

            return Task.CompletedTask;
        },

        OnAuthenticationFailed = context =>
        {
            Console.WriteLine($" Authentication failed: {context.Exception.GetType().Name}");
            Console.WriteLine($"   Message: {context.Exception.Message}");
            if (context.Exception.InnerException != null)
            {
                Console.WriteLine($"   Inner: {context.Exception.InnerException.Message}");
            }
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            Console.WriteLine("Token validated successfully");
            var userName = context.Principal?.Identity?.Name;
            var roles = context.Principal?.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value);
            Console.WriteLine($"   User: {userName}, Roles: {string.Join(", ", roles ?? Array.Empty<string>())}");
            return Task.CompletedTask;
        }
    };
});


// Rule 4: Policy-based authorization
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOrAdmin", policy => policy.RequireRole("User", "Admin"));
    //options.AddPolicy("MinimumAge", policy => policy.RequireRole(new MinimumAgeRequirement(18).ToString()!));
});
//builder.Services.AddAuthorization();

// Rule 7: CORS configuration for trusted origins
builder.Services.AddCors(options =>
{
    options.AddPolicy("TrustedOrigins", policy =>
    {
        policy.WithOrigins("https://localhost:7035", "http://localhost:5130")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});


// Rule 9: Rate limiting configuration
builder.Services.AddMemoryCache();
builder.Services.Configure<IpRateLimitOptions>(options =>
{
    options.GeneralRules = new List<RateLimitRule>
    {
        new RateLimitRule
        {
            Endpoint = "*",
            Limit = 100,
            Period = "1m"
        },
        new RateLimitRule
        {
            Endpoint = "*/api/auth/*",
            Limit = 5,
            Period = "1m"
        }
    };
});


builder.Services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
builder.Services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
builder.Services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();
builder.Services.AddInMemoryRateLimiting();

var app = builder.Build();

app.UseSerilogRequestLogging(options =>
{
    options.GetLevel = (ctx, elapsed, ex) =>
        ex != null ? Serilog.Events.LogEventLevel.Error :
        ctx.Response.StatusCode > 499 ? Serilog.Events.LogEventLevel.Warning :
        Serilog.Events.LogEventLevel.Information;

    options.EnrichDiagnosticContext = (ctx, httpContext) =>
    {
        ctx.Set("RequestHost", string.IsNullOrEmpty(httpContext.Request.Host.Value) ? "Unknown" : httpContext.Request.Host.Value);
        ctx.Set("UserAgent", httpContext.Request.Headers.UserAgent);
        ctx.Set("TraceId", httpContext.TraceIdentifier);
    };
});

static async Task SeedRoles(IServiceProvider services)
{
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

    string[] roles = { "Admin", "User" };

    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }
}


// Rule 8: Suppress detailed errors in production
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error");
    app.UseHsts(); // Rule 11: HSTS header
}

// Rule 1: Enforce HTTPS (should be early in pipeline)
app.UseHttpsRedirection();

// Rule 11: Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "no-referrer");
    context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
    await next();
});

// Swagger (only in development)
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
        options.DisplayRequestDuration();
        options.EnableTryItOutByDefault();
    });
}

// Rule 9: Rate limiting
app.UseIpRateLimiting();

app.UseRouting();

// Rule 7: Apply CORS
app.UseCors("TrustedOrigins");

// CRITICAL: Authentication before Authorization
app.UseAuthentication();
app.UseAuthorization();

app.UseSerilogRequestLogging();

app.MapControllers();

//app.UseMiddleware<AuthMiddleware>();

// Rule 8: Generic error endpoint
app.Map("/error", () => Results.Problem("An error occurred processing your request."));

app.Run();
