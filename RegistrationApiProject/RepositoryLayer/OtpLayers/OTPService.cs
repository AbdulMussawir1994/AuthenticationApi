using Microsoft.EntityFrameworkCore;
using RegistrationApiProject.DatabaseContext;
using RegistrationApiProject.Model;
using RegistrationApiProject.ViewModel;
using System.Threading;

namespace RegistrationApiProject.RepositoryLayer.OtpLayers
{
    public class OTPService : IOTPService
    {
        private readonly DbContextClass _context;

        public OTPService(DbContextClass context)
        {
            _context = context;
        }

        //public async Task SaveOtpAsync(string userId, string code, string name)
        //{
        //    var malaysiaTime = TimeZoneInfo.FindSystemTimeZoneById("Asia/Kuala_Lumpur");
        //    var createdAt = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, malaysiaTime);
        //    var expiresAt = createdAt.AddMinutes(10);

        //    var otp = new OtpModel
        //    {
        //        UserId = userId,
        //        OtpCode = code,
        //        OtpName = name,
        //        CreatedAt = createdAt,
        //        ExpiresAt = expiresAt
        //    };

        //    _context.OtpsDb.Add(otp);
        //    await _context.SaveChangesAsync();
        //}

        public async Task SaveOtpAsync(string userId, string code, string name, string timeZoneId)
        {
            TimeZoneInfo timeZone;
            try
            {
                timeZone = TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
            }
            catch (TimeZoneNotFoundException)
            {
                throw new ArgumentException($"Invalid or unknown time zone: {timeZoneId}");
            }

            var utcNow = DateTimeOffset.UtcNow;
            var createdAt = TimeZoneInfo.ConvertTime(utcNow, timeZone);
            var expiresAt = createdAt.AddMinutes(10);

            // Create the OTP model
            var otp = new OtpModel
            {
                UserId = userId,
                OtpCode = code,
                OtpName = name,
                CreatedAt = createdAt.UtcDateTime, 
                ExpiresAt = expiresAt.UtcDateTime 
            };

            _context.OtpsDb.Add(otp);
            await _context.SaveChangesAsync();
        }

        public async Task<OtpResponseModel> GetOtpAsync(string userId, string code, string name)
        {
            var otp = await _context.OtpsDb
               .Where(o => o.UserId == userId && o.OtpCode == code && o.OtpName == name)
               .OrderByDescending(o => o.Id)
               .Select(o => new { o.OtpCode, o.ExpiresAt })
               .FirstOrDefaultAsync();

            if (otp is null)
            {
                return new OtpResponseModel
                {
                    Status = OtpStatus.NotFound
                };
            }

            if (otp.ExpiresAt <= DateTime.UtcNow)
            {
                return new OtpResponseModel
                {
                    Status = OtpStatus.Expired
                };
            }

            return new OtpResponseModel
            {
                OtpCode = otp.OtpCode,
                ExpiresAt = otp.ExpiresAt,
                Status = OtpStatus.Valid
            };
        }

        public async Task<bool> DeleteOtpAsync(string otpId, string otpCode,string name)
        {
            var otpData = await _context.OtpsDb
                .OrderByDescending (o => o.Id)
                .FirstOrDefaultAsync(o => o.UserId == otpId && o.OtpCode == otpCode  && o.OtpName == name);

            if (otpData is not null)
            {
                _context.OtpsDb.Remove(otpData);
                await _context.SaveChangesAsync();
                return true;
            }

            return false;
        }
    }
}
