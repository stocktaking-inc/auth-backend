using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using stocktaking_auth.Configuration;
using Microsoft.IdentityModel.Tokens;
using stocktaking_auth.Data;
using StackExchange.Redis;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var jwtSettings = builder.Configuration.GetSection(JwtSettings.SectionName).Get<JwtSettings>();
if (jwtSettings == null || string.IsNullOrEmpty(jwtSettings.Key))
{
    throw new InvalidOperationException("JWT configuration is missing or invalid");
}

var redisConnectionString = builder.Configuration.GetSection("Redis:ConnectionString").Value;
if (string.IsNullOrEmpty(redisConnectionString))
{
    throw new InvalidOperationException("Redis connection string is missing");
}

var dbConnectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrEmpty(dbConnectionString))
{
  throw new InvalidOperationException("Database connection string is missing");
}

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection(JwtSettings.SectionName));

builder.Services.AddControllers();

builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseNpgsql(dbConnectionString));

builder.Services.AddSingleton<IConnectionMultiplexer>(
    ConnectionMultiplexer.Connect(redisConnectionString));

builder.Services.AddSingleton(jwtSettings);
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
        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key))
    };
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAuthAndMainApp", builder =>
    {
        builder
            .WithOrigins(
                "http://localhost:5173",  // react
                "http://localhost:3000",  // next
                "https://localhost:8443", // nginx
                "http://localhost:3001"   // next test
            )
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(5100);
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseCors("AllowAuthAndMainApp");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
