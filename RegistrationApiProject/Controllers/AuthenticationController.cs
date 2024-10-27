using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RegistrationApiProject.Model;
using RegistrationApiProject.RepositoryLayer.AuthLayers;
using RegistrationApiProject.RepositoryLayer.OtpLayers;
using RegistrationApiProject.ViewModel;
using System.Text;

namespace RegistrationApiProject.Controllers
{
    [ApiController]
    [ApiVersion("2.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly IAuthenticationLayer _authenticationLayer;
        private readonly IOTPService _otpService;

        public AuthenticationController(
            UserManager<ApplicationUser> userManager,
            IOTPService otpService,
            ILogger<AuthenticationController> logger,
            IAuthenticationLayer _authenticationService)
        {
            _userManager = userManager;
            _logger = logger;
            _authenticationLayer = _authenticationService;
            _otpService = otpService;
        }

        [HttpPost]
        [Route("UserRegister")]
        public async Task<ActionResult> NewUser(RegisterViewModel model)
        {
            try
            {
                var response = await _authenticationLayer.NewUserAsync(model);

                if (!response.Status)
                {
                    return BadRequest(response);
                }

                return StatusCode(StatusCodes.Status200OK, response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        [HttpPost("VerifyEmailOtp")]
        public async Task<IActionResult> VerifyEmailOtpAsync(OtpViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return BadRequest("Invalid user.");
            }

            var otpResponse = await _otpService.GetOtpAsync(user.Id, model.OtpCode, "Email");
            if (otpResponse.Status == OtpStatus.NotFound)
            {
                return BadRequest("OTP not found.");
            }

            if (otpResponse.Status == OtpStatus.Expired)
            {
                return BadRequest("OTP has expired.");
            }

            user.EmailConfirmed = true;
            var updateResult = await _userManager.UpdateAsync(user);

            if (!updateResult.Succeeded)
            {
                return BadRequest("Email confirmation failed.");
            }

            await _otpService.DeleteOtpAsync(user.Id, model.OtpCode, "Email");

            return Ok("Email verified successfully.");
        }

        [HttpPost("VerifySmsOtp")]
        public async Task<IActionResult> VerifySmsOtpAsync(OtpViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return BadRequest("Invalid user.");
            }

            var otpResponse = await _otpService.GetOtpAsync(user.Id, model.OtpCode, "SMS");
            if (otpResponse.Status == OtpStatus.NotFound)
            {
                return BadRequest("OTP not found.");
            }

            if (otpResponse.Status == OtpStatus.Expired)
            {
                return BadRequest("OTP has expired.");
            }

            user.PhoneNumberConfirmed = true;
            var updateResult = await _userManager.UpdateAsync(user);

            if (!updateResult.Succeeded)
            {
                return BadRequest("Mobile no confirmation failed.");
            }

            await _otpService.DeleteOtpAsync(user.Id, model.OtpCode, "SMS");

            return Ok("Mobile no is verified successfully.");
        }

        [HttpPost]
        [Route("Authentication")]
        public async Task<ActionResult> Authentication([FromBody] LoginViewModel model)
        {
            try
            {
                var response = await _authenticationLayer.AuthenticateAsync(model);

                if (!response.Status)
                {
                    return BadRequest(response);
                }

                return StatusCode(StatusCodes.Status200OK, response);
            }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        [HttpPost]
        [Route("PrivacyPolicy")]
        public async Task<IActionResult> IsPrivacyPolicyAgreeAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                return BadRequest("Invalid user ID.");
            }

            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user is null)
                {
                    return BadRequest("User not found.");
                }

                if (user.IsPrivacy)
                {
                    return Ok("Privacy policy already agreed.");
                }

                user.IsPrivacy = true;
                var updateResult = await _userManager.UpdateAsync(user);

                if (!updateResult.Succeeded)
                {
                    _logger.LogWarning("Failed to update user privacy policy agreement for user ID {UserId}", userId);
                    return BadRequest("Failed to update privacy policy agreement.");
                }

                return Ok("Privacy policy agreed successfully.");
            }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException)
            {
                _logger.LogError(ex, "Error occurred while updating privacy policy for user ID {UserId}", userId);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred. Please try again.");
            }
        }

        [HttpPost("SavePassword")]
        public async Task<IActionResult> SavePassword(string userId, [FromBody] string password)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                return BadRequest("User ID cannot be empty.");
            }

            var (isValid, message) = IsValidPassword(password);
            if (!isValid)
            {
                return BadRequest(message);
            }

            bool isSaved = await _authenticationLayer.SavePasswordAsync(userId, password);
            if (isSaved)
            {
                return Ok("Password saved successfully.");
            }

            return BadRequest("Failed to save password. User not found or other error.");
        }

        [HttpPost("VerifyPassword")]
        public async Task<IActionResult> VerifyPassword(string userId, [FromBody] string password)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                return BadRequest("User ID cannot be empty.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return BadRequest("User not found.");
            }

            bool isVerified = await _authenticationLayer.VerifyPasswordAsync(user.Id, password);
            if (isVerified)
            {
                user.IsLoginVerified = true;
                user.FailedPasswordAttempts = 0;
                await _userManager.UpdateAsync(user);
                return Ok("Password verified successfully.");
            }

            user.FailedPasswordAttempts++;
            if (user.FailedPasswordAttempts > 2)
            {
                user.PasswordHash = null;
                user.FailedPasswordAttempts = 0;
                user.IsLoginVerified = false;
                await _userManager.UpdateAsync(user);
                return BadRequest("Password verification failed. Password has been removed due to multiple failed attempts.");
            }

            await _userManager.UpdateAsync(user);
            return BadRequest("Unmatched Pin");
        }

        [HttpPost]
        [Route("ChangePassword")]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            try
            {
                var result = await _authenticationLayer.ChangePasswordAsync(model);

                if (!result.Status)
                {
                    return BadRequest(result);
                }
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        private (bool isValid, string message) IsValidPassword(string password)
        {
            var sb = new StringBuilder();

            if (password.Length != 6)
            {
                sb.AppendLine("Password must be exactly 6 digits.");
            }

            if (!password.All(char.IsDigit))
            {
                sb.AppendLine("Password must contain only digits.");
            }

            if (sb.Length > 0)
            {
                return (false, sb.ToString().Trim());
            }

            return (true, "Password is valid.");
        }

        //private static string CheckPasswordStrength(string pass)
        //{
        //    StringBuilder sb = new StringBuilder();
        //    if (pass.Length < 9)
        //        sb.Append("Minimum password length should be 8" + Environment.NewLine);
        //    if (!(Regex.IsMatch(pass, "[a-z]") && Regex.IsMatch(pass, "[A-Z]") && Regex.IsMatch(pass, "[0-9]")))
        //        sb.Append("Password should be AlphaNumeric" + Environment.NewLine);
        //    if (!Regex.IsMatch(pass, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
        //        sb.Append("Password should contain special charcter" + Environment.NewLine);
        //    return sb.ToString();
        //}

    }
}
