using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using stocktaking_auth.Data;
using stocktaking_auth.Models;
using StackExchange.Redis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace stocktaking_auth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthDbContext _context;
    private readonly IConnectionMultiplexer _redis;
    private readonly IConfiguration _configuration;

    public AuthController(AuthDbContext context, IConnectionMultiplexer redis, IConfiguration configuration)
    {
        _context = context;
        _redis = redis;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (await _context.Profiles.AnyAsync(p => p.Email == request.Email))
            return BadRequest("Email already exists");

        var profile = new Profile
        {
            name = request.Name,
            email = request.Email,
            password_hash = BCrypt.Net.BCrypt.HashPassword(request.Password)
        };

        _context.Profiles.Add(profile);
        await _context.SaveChangesAsync();

        var accessToken = GenerateAccessToken(profile);
        var refreshToken = GenerateRefreshToken();

        var db = _redis.GetDatabase();
        await db.StringSetAsync($"refresh:{profile.id}", refreshToken, TimeSpan.FromDays(30));

        Response.Cookies.Append("AccessToken", accessToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Path = "/",
            Domain = null
        });

        Response.Cookies.Append("RefreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddDays(30)
        });

        return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var profile = await _context.Profiles.FirstOrDefaultAsync(p => p.Email == request.Email);
        if (profile == null || !BCrypt.Net.BCrypt.Verify(request.Password, profile.PasswordHash))
            return Unauthorized("Invalid credentials");

        var accessToken = GenerateAccessToken(profile);
        var refreshToken = GenerateRefreshToken();

        var db = _redis.GetDatabase();
        await db.StringSetAsync($"refresh:{profile.id}", refreshToken, TimeSpan.FromDays(30));

        Response.Cookies.Append("AccessToken", accessToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Path = "/",
            Domain = null
        });

        Response.Cookies.Append("RefreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddDays(30)
        });

        return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        var accessToken = Request.Cookies["AccessToken"];
        var refreshToken = Request.Cookies["RefreshToken"];

        if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(refreshToken))
            return Unauthorized("Missing tokens");

        var principal = GetPrincipalFromExpiredToken(accessToken);
        if (principal == null)
            return Unauthorized("Invalid access token");

        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            return Unauthorized("Invalid access token");

        var db = _redis.GetDatabase();
        var storedRefreshToken = await db.StringGetAsync($"refresh:{userId}");
        if (storedRefreshToken != refreshToken)
            return Unauthorized("Invalid refresh token");

        var profile = await _context.Profiles.FindAsync(int.Parse(userId));
        if (profile == null)
            return Unauthorized("User not found");

        var newAccessToken = GenerateAccessToken(profile);
        var newRefreshToken = GenerateRefreshToken();

        await db.StringSetAsync($"refresh:{profile.Id}", newRefreshToken, TimeSpan.FromDays(30));

        Response.Cookies.Append("AccessToken", newAccessToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddMinutes(5)
        });

        Response.Cookies.Append("RefreshToken", newRefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddDays(30)
        });

        return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken });
    }

    [HttpGet("verify")]
    public IActionResult VerifyToken()
    {
        var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
        var handler = new JwtSecurityTokenHandler();
        try
        {
            handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]))
            }, out _);
            return Ok();
        }
        catch
        {
            return Unauthorized();
        }
    }

    private string GenerateAccessToken(Profile profile)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, profile.Id.ToString()),
            new Claim(ClaimTypes.Email, profile.Email),
            new Claim(ClaimTypes.Name, profile.Name)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(5),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string GenerateRefreshToken()
    {
        return Guid.NewGuid().ToString();
    }

    private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidAudience = _configuration["Jwt:Audience"],
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                return null;

            return principal;
        }
        catch
        {
            return null;
        }
    }
}

public record RegisterRequest(string name, string email, string password);
public record LoginRequest(string email, string password);
