using Microsoft.EntityFrameworkCore;
using stocktaking_auth.Models;

namespace stocktaking_auth.Data;

public class AuthDbContext : DbContext
{
  public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

  public DbSet<profile> Profiles { get; set; }

  protected override void OnModelCreating(ModelBuilder modelBuilder)
  {
    modelBuilder.Entity<profile>(entity =>
    {
      entity.ToTable("profile");
      entity.HasKey(e => e.id);
      entity.Property(e => e.name).HasMaxLength(100).IsRequired();
      entity.Property(e => e.email).HasMaxLength(100).IsRequired();
      entity.Property(e => e.phone).HasMaxLength(20);
      entity.Property(e => e.company).HasMaxLength(100);
      entity.Property(e => e.position).HasMaxLength(100);
      entity.Property(e => e.description).HasColumnType("text");
      entity.Property(e => e.password_hash).HasColumnType("text").IsRequired();
      entity.HasIndex(e => e.settings_id).IsUnique();
    });
  }
}