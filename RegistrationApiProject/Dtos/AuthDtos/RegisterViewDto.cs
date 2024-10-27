namespace RegistrationApiProject.Dtos.AuthDtos;

public record struct RegisterViewDto(string fullName, string identityNo, string emailAddress, string phoneNo);
