namespace RegistrationApiProject.Dtos.AuthDtos;

public record struct RegisterViewDto(string ICId,string fullName, string identityNo, string emailAddress, string phoneNo);
