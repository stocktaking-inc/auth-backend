using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using stocktaking_auth.Configuration;
using stocktaking_auth.Data;

var builder = WebApplication.CreateBuilder(args);

// Validate and get configurations early
var jwtSettings = builder.Configuration.GetSection(JwtSettings.SectionName).Get<JwtSettings>();
if (jwtSettings == null || string.IsNullOrEmpty(jwtSettings.Key))
    throw new InvalidOperationException("JWT configuration is missing or invalid");

var redisConnectionString = builder.Configuration.GetSection("Redis:ConnectionString").Value;
if (string.IsNullOrEmpty(redisConnectionString))
    throw new InvalidOperationException("Redis connection string is missing");

var dbConnectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrEmpty(dbConnectionString))
    throw new InvalidOperationException("Database connection string is missing");

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection(JwtSettings.SectionName));

// Add services
builder.Services.AddControllers();

// EF Core with PostgreSQL
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseNpgsql(dbConnectionString));

// Redis
builder.Services.AddSingleton<IConnectionMultiplexer>(
    ConnectionMultiplexer.Connect(redisConnectionString));

// JWT (using validated settings)
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

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAuthAndMainApp", builder =>
    {
        builder
            .WithOrigins(
                "https://localhost:5173", // Обновлено на HTTPS
                "https://localhost:3000"  // Обновлено на HTTPS
            )
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

// Configure Kestrel for HTTPS
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(5100, listenOptions =>
    {
        listenOptions.UseHttps("cert.pfx", "MyPassword123"); // Используем сертификат
    });
    options.ListenAnyIP(5000); // HTTP порт для fallback
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseCors("AllowAuthAndMainApp");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
