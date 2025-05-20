using System.ComponentModel.DataAnnotations.Schema;

namespace stocktaking_auth.Models;

[Table("profile")]
public class Profile
{
  [Column("id")]
  public int Id { get; set; }
  [Column("name")]
  public string Name { get; set; }
  [Column("email")]
  public string Email { get; set; }
  [Column("phone")]
  public string? Phone { get; set; }
  [Column("company")]
  public string? Company { get; set; }
  [Column("position")]
  public string? Position { get; set; }
  [Column("description")]
  public string? Description { get; set; }
  [Column("password_hash")]
  public string PasswordHash { get; set; }
  [Column("settings_id")]
  public int? SettingsId { get; set; }
  [Column("business_plan_id")]
  public int? BusinessPlanId { get; set; }
}
