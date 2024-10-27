using System.ComponentModel.DataAnnotations;

namespace RegistrationApiProject.ViewModel;

public class ChangePasswordViewModel
{
    [Required]
    [RegularExpression(@"^\d+$", ErrorMessage = "IC Number must be numeric.")]
    public required string ICNumber { get; set; }

    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email format.")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Mobile number is required.")]
    [RegularExpression(@"^\+60\d{9,}$", ErrorMessage = "Mobile number must start with +60 and contain at least 9 additional digits.")]
    public string MobileNo { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "Password must be a 6 digit number.")]
    //[StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long", MinimumLength = 6)]
    public required string Password { get; set; }


    [Display(Name = "Confirm Password")]
    [DataType(DataType.Password)]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "Confirmed Password must be a 6 digit number.")]
    [Compare("Password", ErrorMessage = "Password & Confirmed Password not matched.")]
    public required string VerifyPassword { get; set; }
}
