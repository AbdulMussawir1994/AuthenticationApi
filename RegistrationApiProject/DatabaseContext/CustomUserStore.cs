using Amazon.IdentityManagement.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using RegistrationApiProject.Model;
using Microsoft.EntityFrameworkCore;

namespace RegistrationApiProject.DatabaseContext;

public class CustomUserStore : UserStore<ApplicationUser>
{
    public CustomUserStore(DbContextClass context) : base(context)
    {
    }

    public override Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
    {
        // Allowing non-unique usernames by not requiring them to be unique.
        return Users.SingleOrDefaultAsync(u => u.NormalizedUserName == normalizedUserName, cancellationToken);
    }

    public override Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken = default)
    {
        // Normalize the username before saving.
        user.NormalizedUserName = user.UserName.ToUpperInvariant();
        return base.CreateAsync(user, cancellationToken);
    }

    public override Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken = default)
    {
        // Normalize the username before updating.
        user.NormalizedUserName = user.UserName.ToUpperInvariant();
        return base.UpdateAsync(user, cancellationToken);
    }
}
