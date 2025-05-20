using System.ComponentModel.DataAnnotations;

namespace stocktaking_auth.Dtos.Auth;

public class LoginDto
{
  [Required]
  [EmailAddress]
  public string Email { get; set; } = null!

  [Required]
  [Datatype(DataType.Password)]
  public string Password { get; set; } = null!
}
