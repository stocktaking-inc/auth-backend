using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using stocktaking_auth.Configuration;
using stocktaking_auth.Controllers.DTOs;
using stocktaking_auth.Data;
using stocktaking_auth.Models;

namespace stocktaking_auth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
  private readonly AuthDbContext _context;
  private readonly JwtSettings _jwtSettings;
  private readonly IConnectionMultiplexer _redis;
  private readonly string _frontendUrl;

  public AuthController(
    AuthDbContext context,
    IConnectionMultiplexer redis,
    IOptions<JwtSettings> jwtSettings)
  {
    _context = context;
    _redis = redis;
    _jwtSettings = jwtSettings.Value;
    _frontendUrl = Environment.GetEnvironmentVariable("CORE_FRONTEND_URL") ?? "http://localhost:3000";
  }

  [HttpPost("register")]
  public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
  {
    if (User.Identity?.IsAuthenticated == true)
      return BadRequest(ErrorResponseDto.ValidationError("Cannot register while authenticated"));

    if (!ModelState.IsValid)
      return BadRequest(ErrorResponseDto.ValidationError(ModelState.Values
        .SelectMany(v => v.Errors)
        .Select(e => e.ErrorMessage)
        .FirstOrDefault() ?? "Validation error"));

    if (await _context.Profiles.AnyAsync(p => p.Email == registerDto.Email))
      return BadRequest(ErrorResponseDto.EmailAlreadyExists());

    var profile = new Profile
    {
      Name = registerDto.Name,
      Email = registerDto.Email,
      PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password)
    };

    _context.Profiles.Add(profile);
    await _context.SaveChangesAsync();

    await GenerateAndSetTokens(profile);

    return Redirect($"{_frontendUrl}/dashboard");
  }

  [HttpPost("login")]
  public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
  {
    if (!ModelState.IsValid)
      return BadRequest(ErrorResponseDto.ValidationError(ModelState.Values
        .SelectMany(v => v.Errors)
        .Select(e => e.ErrorMessage)
        .FirstOrDefault() ?? "Validation error"));

    var profile = await _context.Profiles.FirstOrDefaultAsync(p => p.Email == loginDto.Email);
    if (profile == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, profile.PasswordHash))
      return Unauthorized(ErrorResponseDto.InvalidCredentials());

    await GenerateAndSetTokens(profile);

    return Redirect($"{_frontendUrl}/dashboard");
  }

  [HttpPost("refresh")]
  public async Task<IActionResult> Refresh()
  {
    var accessToken = Request.Cookies["AccessToken"];
    var refreshToken = Request.Cookies["RefreshToken"];

    if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(refreshToken))
      return Unauthorized(ErrorResponseDto.MissingTokens());

    var principal = GetPrincipalFromExpiredToken(accessToken);
    if (principal == null)
      return Unauthorized(ErrorResponseDto.InvalidAccessToken());

    var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(userId))
      return Unauthorized(ErrorResponseDto.InvalidAccessToken());

    var db = _redis.GetDatabase();
    var storedRefreshToken = await db.StringGetAsync($"refresh:{userId}");
    if (storedRefreshToken != refreshToken)
      return Unauthorized(ErrorResponseDto.InvalidRefreshToken());

    if (!int.TryParse(userId, out var userIdInt))
      return Unauthorized(ErrorResponseDto.InvalidAccessToken());

    var profile = await _context.Profiles.FindAsync(userIdInt);
    if (profile == null)
      return Unauthorized(ErrorResponseDto.UserNotFound());

    var newAccessToken = GenerateAccessToken(profile);
    var newRefreshToken = GenerateRefreshToken();

    await Task.WhenAll(
      db.StringSetAsync($"refresh:{profile.Id}", newRefreshToken,
        TimeSpan.FromDays(_jwtSettings.RefreshTokenExpirationDays)),
      db.StringSetAsync($"refresh-token-mapping:{newRefreshToken}", profile.Id.ToString(),
        TimeSpan.FromDays(_jwtSettings.RefreshTokenExpirationDays))
    );

    Response.Cookies.Append("AccessToken", newAccessToken, new CookieOptions
    {
      HttpOnly = true,
      Secure = true,
      SameSite = SameSiteMode.None,
      Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
      Path = "/"
    });

    Response.Cookies.Append("RefreshToken", newRefreshToken, new CookieOptions
    {
      HttpOnly = true,
      Secure = true,
      SameSite = SameSiteMode.None,
      Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
      Path = "/"
    });

    return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken });
  }

  [HttpPost("refresh-access")]
  public async Task<IActionResult> RefreshAccessToken()
  {
    var refreshToken = Request.Cookies["RefreshToken"];
    if (string.IsNullOrEmpty(refreshToken))
      return Unauthorized(ErrorResponseDto.MissingTokens());

    var db = _redis.GetDatabase();
    var userId = await db.StringGetAsync($"refresh-token-mapping:{refreshToken}");

    if (userId.IsNullOrEmpty)
      return Unauthorized(ErrorResponseDto.InvalidRefreshToken());

    if (!int.TryParse(userId, out var userIdInt))
      return Unauthorized(ErrorResponseDto.InvalidRefreshToken());

    var profile = await _context.Profiles.FindAsync(userIdInt);
    if (profile == null)
      return Unauthorized(ErrorResponseDto.UserNotFound());

    var newAccessToken = GenerateAccessToken(profile);

    Response.Cookies.Append("AccessToken", newAccessToken, new CookieOptions
    {
      HttpOnly = true,
      Secure = true,
      SameSite = SameSiteMode.None,
      Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
      Path = "/"
    });

    return Ok(new { AccessToken = newAccessToken });
  }

  [HttpPost("logout")]
  public async Task<IActionResult> Logout()
  {
    var refreshToken = Request.Cookies["RefreshToken"];
    if (!string.IsNullOrEmpty(refreshToken))
    {
      var db = _redis.GetDatabase();
      var userId = await db.StringGetAsync($"refresh-token-mapping:{refreshToken}");

      if (!userId.IsNullOrEmpty)
        await Task.WhenAll(
          db.KeyDeleteAsync($"refresh:{userId}"),
          db.KeyDeleteAsync($"refresh-token-mapping:{refreshToken}")
        );
    }

    Response.Cookies.Delete("AccessToken");
    Response.Cookies.Delete("RefreshToken");

    return Redirect($"{_frontendUrl}/login");
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
        ValidIssuer = _jwtSettings.Issuer,
        ValidAudience = _jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key))
      }, out _);
      return Ok();
    }
    catch
    {
      return Unauthorized(ErrorResponseDto.Unauthorized());
    }
  }

  private async Task GenerateAndSetTokens(Profile profile)
  {
    var accessToken = GenerateAccessToken(profile);
    var refreshToken = GenerateRefreshToken();

    var db = _redis.GetDatabase();
    await Task.WhenAll(
      db.StringSetAsync($"refresh:{profile.Id}", refreshToken,
        TimeSpan.FromDays(_jwtSettings.RefreshTokenExpirationDays)),
      db.StringSetAsync($"refresh-token-mapping:{refreshToken}", profile.Id.ToString(),
        TimeSpan.FromDays(_jwtSettings.RefreshTokenExpirationDays))
    );

    Response.Cookies.Append("AccessToken", accessToken, new CookieOptions
    {
      HttpOnly = true,
      Secure = true,
      SameSite = SameSiteMode.None,
      Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
      Path = "/"
    });

    Response.Cookies.Append("RefreshToken", refreshToken, new CookieOptions
    {
      HttpOnly = true,
      Secure = true,
      SameSite = SameSiteMode.None,
      Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
      Path = "/"
    });
  }

  private string GenerateAccessToken(Profile profile)
  {
    var claims = new[]
    {
      new Claim(ClaimTypes.NameIdentifier, profile.Id.ToString()),
      new Claim(ClaimTypes.Email, profile.Email),
      new Claim(ClaimTypes.Name, profile.Name)
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
      _jwtSettings.Issuer,
      _jwtSettings.Audience,
      claims,
      expires: DateTime.Now.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
      signingCredentials: creds);

    return new JwtSecurityTokenHandler().WriteToken(token);
  }

  private string GenerateRefreshToken()
  {
    return Guid.NewGuid().ToString();
  }

  private ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
  {
    var tokenValidationParameters = new TokenValidationParameters
    {
      ValidateAudience = true,
      ValidateIssuer = true,
      ValidateIssuerSigningKey = true,
      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key)),
      ValidIssuer = _jwtSettings.Issuer,
      ValidAudience = _jwtSettings.Audience,
      ValidateLifetime = false
    };

    var tokenHandler = new JwtSecurityTokenHandler();
    try
    {
      var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
      if (securityToken is not JwtSecurityToken jwtSecurityToken ||
          !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
            StringComparison.InvariantCultureIgnoreCase))
        return null;

      return principal;
    }
    catch
    {
      return null;
    }
  }
}
