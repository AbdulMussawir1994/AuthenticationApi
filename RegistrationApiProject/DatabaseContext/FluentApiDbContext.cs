
using FluentValidation;
using RegistrationApiProject.Model;

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
