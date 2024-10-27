using System.ComponentModel.DataAnnotations;

namespace RegistrationApiProject.ViewModel;

public class LoginViewModel
{
    [Required]
    [RegularExpression(@"^\d+$", ErrorMessage = "IC Number must be numeric.")]
    public required string ICNumber { get; set; }

    [Required]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "Password must be a 6 digit number.")]
    public required string Password { get; set; }
}
