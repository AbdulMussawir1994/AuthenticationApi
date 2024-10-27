using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace RegistrationApiProject.Model;

[Index(nameof(IcNumber), IsUnique = true)]
public class ApplicationUser : IdentityUser
{
    public string IcNumber { get; set; }
    public bool IsPrivacy { get; set; } = false;
    public bool IsLoginVerified { get; set; } = false;
    public int FailedPasswordAttempts { get; set; } = 0;
    public DateTime DateCreated { get; private set; } = DateTime.UtcNow;
    public DateTime DateModified { get; set; } = DateTime.UtcNow;

    public void UpdateModifiedDate() => DateModified = DateTime.UtcNow;
}
