namespace RegistrationApiProject.ViewModel;

public class TokenViewModel
{
    public bool Status { get; set; } = false;
    public string Message { get; set; } = string.Empty;
    public string AccessToken { get; set; } = null;
}
