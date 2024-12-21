using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.EntityFrameworkCore.Infrastructure;
using RegistrationApiProject.Model;

namespace RegistrationApiProject.DatabaseContext;

public class DbContextClass : IdentityDbContext<ApplicationUser>
{
    private readonly ILogger<DbContextClass> _logger;

    public DbContextClass(DbContextOptions<DbContextClass> options, ILogger<DbContextClass> logger) : base(options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        try
        {
            var databaseCreator = Database.GetService<IDatabaseCreator>() as RelationalDatabaseCreator;
            if (databaseCreator != null)
            {
                if (!databaseCreator.CanConnect())
                {
                    databaseCreator.Create();
                }
                if (!databaseCreator.HasTables())
                {
                    databaseCreator.CreateTables();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while initializing the database.");
        }
    }

    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        foreach (var entry in ChangeTracker.Entries<ApplicationUser>())
        {
            if (entry.State == EntityState.Modified)
            {
                entry.Entity.DateModified = DateTime.UtcNow;
            }
        }

        return await base.SaveChangesAsync(cancellationToken);
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>(entity =>
        {
            entity.HasIndex(u => u.IcNumber).IsUnique();
            entity.HasIndex(u => u.Email).IsUnique();
            entity.HasIndex(u => u.UserName).IsUnique();
            entity.HasIndex(u => u.PhoneNumber).IsUnique();

            entity.Property(e => e.IcNumber)
                  .IsRequired()
                  .HasMaxLength(12);

            entity.Property(e => e.DateCreated)
                  .HasDefaultValueSql("GETUTCDATE()");
        });

    }

    public DbSet<OtpModel> OtpsDb => Set<OtpModel>();
}
