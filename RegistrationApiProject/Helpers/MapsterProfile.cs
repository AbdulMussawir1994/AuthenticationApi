using Mapster;
using RegistrationApiProject.Dtos.AuthDtos;
using RegistrationApiProject.ViewModel;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory.Database;

namespace RegistrationApiProject.Helpers;

public sealed class MapsterProfile : TypeAdapterConfig
{
    public MapsterProfile()
    {

        //// User Mapster
        TypeAdapterConfig<RegisterViewModel, RegisterViewDto>.NewConfig()
         .Map(dest => dest.fullName, src => src.Username)
         .Map(dest => dest.emailAddress, src => src.Email)
         .Map(dest => dest.identityNo, src => src.IcNumber)
         .Map(dest => dest.phoneNo, src => src.MobileNo);

    }
}