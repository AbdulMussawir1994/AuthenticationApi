using Microsoft.AspNetCore.Mvc;
using RegistrationApiProject.Dtos.AuthDtos;
using RegistrationApiProject.ModelConverter;
using RegistrationApiProject.ViewModel;

namespace RegistrationApiProject.RepositoryLayer.AuthLayers;

public interface IAuthenticationLayer
{
    Task<TokenViewModel> AuthenticateAsync(LoginViewModel loginModel);
    Task<ResponseObj<RegisterViewDto>> NewUserAsync(RegisterViewModel model); //IUrlHelper urlHelper
    Task<bool> SavePasswordAsync(string userId, string password);
    Task<bool> VerifyPasswordAsync(string userId, string password);
    Task<ResponseObj<bool>> ChangePasswordAsync(ChangePasswordViewModel model);
}
