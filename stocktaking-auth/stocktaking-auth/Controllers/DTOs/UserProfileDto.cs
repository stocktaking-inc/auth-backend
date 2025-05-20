namespace stocktaking_auth.Dtos.Auth;

public class UserProfileDto
{
    public UserProfileDto() { }

    public UserProfileDto(Profile profile)
    {
        Id = profile.id;
        Name = profile.name;
        Email = profile.email;
    }

    public int Id { get; set; }
    public string Name { get; set; } = null!;
    public string Email { get; set; } = null!;
}
