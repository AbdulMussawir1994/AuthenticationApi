using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RegistrationApiProject.DatabaseContext;
using RegistrationApiProject.Dtos.AuthDtos;
using RegistrationApiProject.Model;
using RegistrationApiProject.ModelConverter;
using RegistrationApiProject.ViewModel;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using RegistrationApiProject.RepositoryLayer.EmailLayers;
using Microsoft.EntityFrameworkCore.Storage;
using RegistrationApiProject.RepositoryLayer.OtpLayers;
using RegistrationApiProject.RepositoryLayer.SMSLayers;
using System.Security;
using Amazon.IdentityManagement.Model;

namespace RegistrationApiProject.RepositoryLayer.AuthLayers
{
    public class AuthenticationLayer : IAuthenticationLayer
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly DbContextClass _context;
        private readonly EmailService _emailService;
        private readonly IOTPService _otpService;
        private readonly SmsService _smsService;
        private readonly PasswordHasher<ApplicationUser> _passwordHasher;
        private readonly HashSet<string> _OTPCode = new HashSet<string>();

        public AuthenticationLayer(
        UserManager<ApplicationUser> userManager,
        DbContextClass applicationDbContext, IOTPService otpService, SmsService smsService,
        IConfiguration configuration, EmailService emailService)
        {
            _userManager = userManager;
            _configuration = configuration;
            _context = applicationDbContext;
            _emailService = emailService;
            _otpService = otpService;
            _passwordHasher = new PasswordHasher<ApplicationUser>();
        }

        public async Task<ResponseObj<RegisterViewDto>> NewUserAsync(RegisterViewModel model)
        {
            // Check if user already exists
            var existingUser = await _userManager.Users.FirstOrDefaultAsync(u => u.IcNumber == model.IcNumber);

            if (existingUser is not null)
            {
                return await ExistingUserAsync(existingUser, model);
            }

            return await RegisterNewUserAsync(model);
        }

        private async Task<ResponseObj<RegisterViewDto>> ExistingUserAsync(ApplicationUser existingUser, RegisterViewModel model)
        {
            if (existingUser.EmailConfirmed || existingUser.PhoneNumberConfirmed)
            {
                return new ResponseObj<RegisterViewDto>
                {
                    Status = false,
                    Message = "This IC Number already exists with a verified email or phone number."
                };
            }

            // Update user details if necessary
            existingUser.Email = model.Email;
            existingUser.UserName = model.Username;
            existingUser.PhoneNumber = model.MobileNo;

            var updateResult = await _userManager.UpdateAsync(existingUser);
            if (!updateResult.Succeeded)
            {
                return new ResponseObj<RegisterViewDto>
                {
                    Status = false,
                    Message = "Failed to update existing user information.",
                    Errors = updateResult.Errors.Select(e => e.Description).ToList()
                };
            }

            // Send OTPs
            await SendOtpAsync(existingUser.Id, existingUser.Email, existingUser.PhoneNumber);

            // Prepare response
            return new ResponseObj<RegisterViewDto>
            {
                Value = new RegisterViewDto
                {
                    ICId = existingUser.Id,
                    ICNum = existingUser.IcNumber
                },
                Status = true,
                Message = "OTP has been sent to the existing user for verification."
            };
        }

        // Method for registering a new user
        private async Task<ResponseObj<RegisterViewDto>> RegisterNewUserAsync(RegisterViewModel model)
        {

            //bool isMobileConfirmed = await _userManager.Users.AnyAsync(user => user.PhoneNumber == model.MobileNo);
            //if (isMobileConfirmed)
            //{
            //    return new ResponseObj<RegisterViewDto>
            //    {
            //        Status = false,
            //        Message = "Mobile no is already registered."
            //    };
            //}

            var duplicateUser = await _userManager.Users
                .Where(user => user.Email == model.Email || user.PhoneNumber == model.MobileNo || user.UserName == model.Username)
                .Select(user => new { IsEmailMatch = user.Email == model.Email, IsPhoneMatch = user.PhoneNumber == model.MobileNo, IsUsernameMatch = user.UserName == model.Username }) 
                .FirstOrDefaultAsync();

            if (duplicateUser != null)
            {
                string message = duplicateUser.IsEmailMatch ? "Email is already registered." : duplicateUser.IsPhoneMatch  ? "Mobile no is already registered." : "This User is already registered.";

                return new ResponseObj<RegisterViewDto>
                {
                    Status = false,
                    Message = message
                };
            }

            var user = new ApplicationUser
            {
                UserName = model.Username,
                IcNumber = model.IcNumber,
                PhoneNumber = model.MobileNo,
                Email = model.Email,
                EmailConfirmed = false,
                PhoneNumberConfirmed = false,
                DateCreated = DateTime.Now,
            };

            var executionStrategy = _context.Database.CreateExecutionStrategy();

            return await executionStrategy.ExecuteAsync(async () =>
            {
                await using var transaction = await _context.Database.BeginTransactionAsync();
                try
                {
                    var result = await _userManager.CreateAsync(user);
                    if (!result.Succeeded)
                    {
                        return new ResponseObj<RegisterViewDto>
                        {
                            Status = false,
                            Message = "User registration failed.",
                            Errors = result.Errors.Select(e => e.Description).ToList()
                        };
                    }

                    await SendOtpAsync(user.Id, user.Email, user.PhoneNumber);
                    await transaction.CommitAsync();

                    return new ResponseObj<RegisterViewDto>
                    {
                        Value = new RegisterViewDto
                        {
                            ICId = user.Id,
                            ICNum = user.IcNumber
                        },
                        Status = true,
                        Message = "Registration successful. Please verify your Email & Mobile number."
                    };
                }
                catch (Exception ex)
                {
                    await transaction.RollbackAsync();
                    return new ResponseObj<RegisterViewDto>
                    {
                        Status = false,
                        Message = "An error occurred during registration. Please try again."
                    };
                }
            });
        }

        // Helper method for generating and sending OTPs
        private async Task SendOtpAsync(string userId, string email, string phoneNumber)
        {
            var emailOtp = GenerateVerificationCode();
            await _otpService.SaveOtpAsync(userId, emailOtp, "Email", "Asia/Karachi");
            await _emailService.SendOtpAsync(email, emailOtp);

            var mobileOtp = GenerateVerificationCode();
            await _otpService.SaveOtpAsync(userId, mobileOtp, "SMS", "Asia/Karachi");
            // Uncomment to send SMS
            // await _smsService.SendMobileVerificationCodeAsync(phoneNumber, mobileOtp);
        }

        private string GenerateVerificationCode()
        {
            string otp;

            do
            {
                byte[] randomNumber = new byte[4];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(randomNumber);
                }

                otp = (Math.Abs(BitConverter.ToInt32(randomNumber, 0)) % 9000 + 1000).ToString();
            }

            while (_OTPCode.Contains(otp));

            _OTPCode.Add(otp);
            return otp;
        }

        //private string GenerateVerificationCode()
        //{
        //    byte[] randomNumber = new byte[4];
        //    using (var rng = RandomNumberGenerator.Create())
        //    {
        //        rng.GetBytes(randomNumber);
        //    }

        //    int value = BitConverter.ToInt32(randomNumber, 0);
        //    int otp = Math.Abs(value % 900000) + 100000;

        //    return otp.ToString();
        //}

        //private string GenerateVerificationCode()
        //{
        //    byte[] randomNumber = new byte[4];
        //    using (var rng = RandomNumberGenerator.Create())
        //    {
        //        rng.GetBytes(randomNumber);
        //    }

        //    // Generate a 4-digit number by constraining the value to the range 1000 - 9999
        //    int otp = Math.Abs(BitConverter.ToInt32(randomNumber, 0)) % 9000 + 1000;

        //    return otp.ToString();
        //}

        public async Task<bool> SavePasswordAsync(string userId, string password)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user is null) return false;

            var currentPass= user.PasswordHash;
            var newPass = _passwordHasher.HashPassword(user, password);

            if (currentPass == newPass)
                return true;

            user.PasswordHash = newPass;

            var updateResult = await _userManager.UpdateAsync(user);
            return updateResult.Succeeded;
        }

        public async Task<bool> VerifyPasswordAsync(string userId, string password)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user?.PasswordHash is null) return false;

            var verificationResult = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
            return verificationResult switch
            {
                PasswordVerificationResult.Success => true,
                PasswordVerificationResult.SuccessRehashNeeded => true,
                _ => false
            };
        }

        public async Task<TokenViewModel> AuthenticateAsync(LoginViewModel model)
        {
            var tokenViewModel = new TokenViewModel();

            try
            {
                var user = await _userManager.Users.SingleOrDefaultAsync(x => x.IcNumber == model.ICNumber);
                if (user is null)
                {
                    tokenViewModel.Status = false;
                    tokenViewModel.Message = "Invalid IC-Number";
                    return tokenViewModel;
                }

                if (!user.IsLoginVerified || !user.IsPrivacy)
                {
                    var messages = new List<string>();
                    if (!user.IsLoginVerified)
                        messages.Add("Please first verify your password");
                    if (!user.IsPrivacy)
                        messages.Add("Please confirm the privacy policy.");

                    tokenViewModel.Status = false;
                    tokenViewModel.Message = string.Join(" and ", messages);

                    int messageCount = messages.Count; // Store count to avoid repeated calls

                    // Set AccessToken based on the number of messages
                    tokenViewModel.AccessToken = messageCount == 1 ? "1" : messageCount >= 2 ? "2" : string.Empty;
                    return tokenViewModel;
                }

                var isPasswordValid = await _userManager.CheckPasswordAsync(user, model.Password);
                if (!isPasswordValid)
                {
                    tokenViewModel.Status = false;
                    tokenViewModel.Message = "Invalid Password";
                    return tokenViewModel;
                }

                if (user.EmailConfirmed || user.PhoneNumberConfirmed)
                {

                    var authClaims = new List<Claim>
                    {
                            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()), // User ID
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // Unique token ID
                    };

                    tokenViewModel.AccessToken = GenerateJwtToken(authClaims);
                    tokenViewModel.Status = true;
                    tokenViewModel.Message = "Success";
                }
                else
                {
                    await HandleVerificationAsync(user);

                    tokenViewModel.AccessToken = "No Access Allowed";
                    tokenViewModel.Status = false;
                    tokenViewModel.Message = "Please confirm Email or Mobile no to access Login";
                }

            }
            catch (Exception ex)
            {
                tokenViewModel.Status = false;
                tokenViewModel.Message = "Error: " + ex.Message;
            }

            return tokenViewModel;
        }

        private async Task HandleVerificationAsync(dynamic user)
        {
            if (!user.EmailConfirmed)
            {
                var emailOtp = GenerateVerificationCode();
                await _otpService.SaveOtpAsync(user.Id, emailOtp, "Email", "Asia/Karachi");
                await _emailService.SendOtpAsync(user.Email, emailOtp);
            }

            if (!user.PhoneNumberConfirmed)
            {
                var mobileOtp = GenerateVerificationCode();
                await _otpService.SaveOtpAsync(user.Id, mobileOtp, "SMS", "Asia/Karachi");
               // await _smsService.SendMobileVerificationCodeAsync(user.MobileNo, mobileOtp);
            }
        }

        private string GenerateJwtToken(IEnumerable<Claim> claims)
        {
            var secretKey = _configuration["JWTKey:Secret"];
            if (string.IsNullOrEmpty(secretKey) || secretKey.Length < 64) // 512 bits required for HS512
            {
                throw new SecurityException("JWT secret key must be at least 64 characters long for HS512.");
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenExpiryInMinutes = Convert.ToInt64(_configuration["JWTKey:TokenExpiryTimeInMinutes"]);

            var securityClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(tokenExpiryInMinutes).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64), // Expiration
                new Claim(JwtRegisteredClaimNames.Nbf, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            // Combine with provided user claims
            securityClaims.AddRange(claims);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = _configuration["JWTKey:ValidIssuer"],
                Audience = _configuration["JWTKey:ValidAudience"],
                Expires = DateTime.UtcNow.AddMinutes(tokenExpiryInMinutes),
                SigningCredentials = signingCredentials,
                Subject = new ClaimsIdentity(securityClaims),
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(securityToken);
        }

        public async Task<ResponseObj<bool>> ChangePasswordAsync(ChangePasswordViewModel model)
        {
            var response = new ResponseObj<bool>();

            try
            {
                var strategy = _context.Database.CreateExecutionStrategy();
                await strategy.ExecuteAsync(async () =>
                {
                    await using var transaction = await _context.Database.BeginTransactionAsync();

                    var user = await _userManager.Users
                        .SingleOrDefaultAsync(x => x.IcNumber == model.ICNumber && x.PhoneNumber == model.MobileNo && x.Email == model.Email);

                    if (user is null)
                    {
                        response.Message = "Please provide correct IC Number, Mobile No, and Email.";
                        response.Status = false;
                        return;
                    }

                    var removePasswordResult = await _userManager.RemovePasswordAsync(user);
                    if (!removePasswordResult.Succeeded)
                    {
                        response.Message = "Error removing the old password.";
                        response.Status = false;
                        return;
                    }

                    var addPasswordResult = await _userManager.AddPasswordAsync(user, model.Password);
                    if (!addPasswordResult.Succeeded)
                    {
                        response.Message = "Error adding the new password.";
                        response.Status = false;
                        return;
                    }

                    // Set verification flags
                    user.IsLoginVerified = true;
                    user.EmailConfirmed = false;
                    user.PhoneNumberConfirmed = false;

                    await HandleVerificationAsync(user);
                    await transaction.CommitAsync();

                    response.Message = "Password has been updated successfully. You will receive an OTP on Email/Mobile to verify the new password.";
                    response.Status = true;
                });
            }
            catch (Exception ex)
            {
                response.Status = false;
                response.Message = "Error: " + ex.Message;
            }

            return response;
        }

        //private string GenerateJwtToken(IEnumerable<Claim> claims)
        //{
        //    var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["JWTKey:Secret"]));
        //    var tokenExpiryInMinutes = Convert.ToInt64(_configuration["JWTKey:TokenExpiryTimeInMinutes"]);

        //    var tokenDescriptor = new SecurityTokenDescriptor
        //    {
        //        Issuer = _configuration["JWTKey:ValidIssuer"],
        //        Audience = _configuration["JWTKey:ValidAudience"],
        //        Expires = DateTime.UtcNow.AddMinutes(tokenExpiryInMinutes),
        //        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
        //        Subject = new ClaimsIdentity(claims),
        //    };

        //    var tokenHandler = new JwtSecurityTokenHandler();
        //    var token = tokenHandler.CreateToken(tokenDescriptor);
        //    return tokenHandler.WriteToken(token);
        //}
    }
}
