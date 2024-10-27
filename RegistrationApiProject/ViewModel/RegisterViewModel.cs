using System.ComponentModel.DataAnnotations;

namespace RegistrationApiProject.ViewModel;

public class RegisterViewModel
{
    [Required(ErrorMessage = "Username is required.")]
    [StringLength(50, MinimumLength = 6, ErrorMessage = "Username must be at least 6 characters long.")]
    public string Username { get; set; }

    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email format.")]
    public string Email { get; set; }

    [Required(ErrorMessage = "IC Number is required.")]
    [RegularExpression(@"^\d{12,}$", ErrorMessage = "IC Number must be a numeric value with at least 12 digits.")]
    public string IcNumber { get; set; }

    [Required(ErrorMessage = "Mobile number is required.")]
    [RegularExpression(@"^\+60\d{9,}$", ErrorMessage = "Mobile number must start with +60 and contain at least 9 additional digits.")]
    public string MobileNo { get; set; }
}