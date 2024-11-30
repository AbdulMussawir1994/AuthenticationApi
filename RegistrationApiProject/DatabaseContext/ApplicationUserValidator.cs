using FluentValidation;
using RegistrationApiProject.Model;

namespace RegistrationApiProject.DatabaseContext;

public class ApplicationValidator : AbstractValidator<ApplicationUser>
{
    public ApplicationValidator()
    {
        RuleFor(user => user.IcNumber)
            .NotEmpty().WithMessage("IC Number is required.")
            .Length(5, 20).WithMessage("IC Number must be between 5 and 20 characters.");

        RuleFor(user => user.IsPrivacy)
            .NotNull().WithMessage("Privacy setting must be specified.");

        RuleFor(user => user.IsLoginVerified)
            .NotNull().WithMessage("Login verification status must be specified.");

        RuleFor(user => user.FailedPasswordAttempts)
            .GreaterThanOrEqualTo(0).WithMessage("Failed password attempts cannot be negative.");

        RuleFor(user => user.DateCreated)
            .NotNull().WithMessage("DateCreated must be provided.");

        RuleFor(user => user.DateModified)
            .NotNull().WithMessage("DateModified must be provided.");
    }
}