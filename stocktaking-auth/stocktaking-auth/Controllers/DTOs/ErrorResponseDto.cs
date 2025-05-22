namespace stocktaking_auth.Controllers.DTOs;

public class ErrorResponseDto
{
  public string Message { get; set; } = string.Empty;

  public static ErrorResponseDto EmailAlreadyExists()
  {
    return new ErrorResponseDto
    {
      Message = "Email already exists"
    };
  }

  public static ErrorResponseDto InvalidCredentials()
  {
    return new ErrorResponseDto
    {
      Message = "Invalid credentials"
    };
  }

  public static ErrorResponseDto MissingTokens()
  {
    return new ErrorResponseDto
    {
      Message = "Missing tokens"
    };
  }

  public static ErrorResponseDto InvalidAccessToken()
  {
    return new ErrorResponseDto
    {
      Message = "Invalid access token"
    };
  }

  public static ErrorResponseDto InvalidRefreshToken()
  {
    return new ErrorResponseDto
    {
      Message = "Invalid refresh token"
    };
  }

  public static ErrorResponseDto UserNotFound()
  {
    return new ErrorResponseDto
    {
      Message = "User not found"
    };
  }

  public static ErrorResponseDto Unauthorized()
  {
    return new ErrorResponseDto
    {
      Message = "Unauthorized"
    };
  }

  public static ErrorResponseDto ValidationError(string message)
  {
    return new ErrorResponseDto
    {
      Message = message
    };
  }
}
