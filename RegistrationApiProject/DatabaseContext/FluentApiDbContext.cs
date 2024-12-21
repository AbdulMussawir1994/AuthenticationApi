
using FluentValidation;
using RegistrationApiProject.Model;
using RegistrationApiProject.ViewModel;

namespace RegistrationApiProject.DatabaseContext;

public class ApplicationUserValidator : AbstractValidator<ApplicationUser>
{
    public ApplicationUserValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Invalid email format.")
            .MaximumLength(256);

        RuleFor(x => x.IcNumber)
            .NotEmpty().WithMessage("IC Number is required.")
            .Matches(@"^\d{12}$").WithMessage("IC Number must be exactly 12 digits.");

        RuleFor(x => x.PhoneNumber)
            .MaximumLength(15).WithMessage("Phone number cannot exceed 15 characters.")
            .Matches(@"^\+60\d{9,}$").When(x => !string.IsNullOrEmpty(x.PhoneNumber))
            .WithMessage("Phone number must start with +60 and have at least 9 digits.");
    }
}

public class RegisterViewModelValidator : AbstractValidator<RegisterViewModel>
{
    public RegisterViewModelValidator()
    {
        RuleFor(x => x.IcNumber)
            .NotEmpty().WithMessage("IC Number is required.")
            .Length(12).WithMessage("IC Number must be exactly 12 characters.")
            .Matches("^[0-9]+$").WithMessage("IC Number must contain only digits.");

        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Invalid email format.");

        RuleFor(x => x.Username)
            .NotEmpty().WithMessage("Username is required.")
            .Length(3, 50).WithMessage("Username must be between 3 and 50 characters.");

        RuleFor(x => x.MobileNo)
            .NotEmpty().WithMessage("Mobile number is required.")
          //  .Matches("^[0-9]+$").WithMessage("Mobile number must contain only digits.")
            .Length(10, 15).WithMessage("Mobile number must be between 10 and 15 digits.");
    }
}



public class OtpModelValidator : AbstractValidator<OtpModel>
{
    public OtpModelValidator()
    {
        RuleFor(x => x.OtpCode)
            .NotEmpty().WithMessage("OTP Code is required.")
            .Length(4).WithMessage("OTP Code must be exactly 4 digits.");

        RuleFor(x => x.ExpiresAt)
            .NotEmpty().WithMessage("Expiration date is required.")
            .GreaterThan(DateTime.UtcNow).WithMessage("Expiration date must be in the future.");
    }
}
