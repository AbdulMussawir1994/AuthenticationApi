namespace RegistrationApiProject.ViewModel;

public class OtpResponseModel
{
    public string OtpCode { get; set; }
    public DateTime ExpiresAt { get; set; }
    public OtpStatus Status { get; set; }
}

public enum OtpStatus
{
    Valid,
    Expired,
    NotFound
}
