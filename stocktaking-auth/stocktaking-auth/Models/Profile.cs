namespace stocktaking_auth.Models;

public class profile
{
  public int id { get; set; }
  public string name { get; set; }
  public string email { get; set; }
  public string? phone { get; set; }
  public string? company { get; set; }
  public string? position { get; set; }
  public string? description { get; set; }
  public string password_hash { get; set; }
  public int? settings_id { get; set; }
  public int? business_plan_id { get; set; }
}