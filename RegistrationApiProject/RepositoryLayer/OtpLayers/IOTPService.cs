﻿using RegistrationApiProject.ViewModel;

namespace RegistrationApiProject.RepositoryLayer.OtpLayers
{
    public interface IOTPService
    {
        Task SaveOtpAsync(string userId, string code, string name);
        Task<OtpResponseModel> GetOtpAsync(string userId, string code, string name);
        Task<bool> DeleteOtpAsync(string userId, string otpCode,string name);
    }
}
