using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace RegistrationApiProject.Model;

[Index(nameof(IcNumber), IsUnique = true)]
public class ApplicationUser : IdentityUser
{
    public string IcNumber { get; set; }
    public bool IsPrivacy { get; set; } = false;
    public bool IsLoginVerified { get; set; } = false;
    public int FailedPasswordAttempts { get; set; } = 0;

    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public DateTime DateCreated { get; set; } = DateTime.UtcNow;

    public DateTime? DateModified { get; set; } // Nullable DateModified

    //   public void UpdateModifiedDate() => DateModified = DateTime.UtcNow;
}
