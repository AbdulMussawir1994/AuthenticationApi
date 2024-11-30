using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.EntityFrameworkCore;
using RegistrationApiProject.Model;
using Microsoft.EntityFrameworkCore.Infrastructure;
using System.Reflection.Emit;

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
                if (!databaseCreator.CanConnect()) databaseCreator.Create();
                if (!databaseCreator.HasTables()) databaseCreator.CreateTables();
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
                entry.Entity.UpdateModifiedDate();
            }
        }
        return await base.SaveChangesAsync(cancellationToken);
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Ensure IC number is unique in ApplicationUser
        builder.Entity<ApplicationUser>()
            .HasIndex(u => u.IcNumber)
        .IsUnique();

        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(e => e.IcNumber)
                  .IsRequired()
                  .HasMaxLength(12); // Assuming Malaysian IC length

            entity.HasIndex(e => e.IcNumber)
                  .IsUnique();

            entity.Property(e => e.DateCreated)
                  .HasDefaultValueSql("GETUTCDATE()");

            entity.Property(e => e.DateModified)
                  .HasDefaultValueSql("GETUTCDATE()")
                  .ValueGeneratedOnAddOrUpdate();
        });
    }

    public DbSet<OtpModel> OtpsDb => Set<OtpModel>();
}