using System.ComponentModel.DataAnnotations;

namespace stocktaking_auth.Controllers.DTOs;

public class RegisterDto
{
  [Required]
  [StringLength(100, MinimumLength = 2)]
  public string Name { get; set; } = null!;

  [Required] [EmailAddress] public string Email { get; set; } = null!;

  [Required]
  [StringLength(100, MinimumLength = 6)]
  [DataType(DataType.Password)]
  public string Password { get; set; } = null!;
}
