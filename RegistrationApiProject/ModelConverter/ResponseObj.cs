namespace RegistrationApiProject.ModelConverter;

public class ResponseObj<T>
{
    public T Value { get; set; }
    public bool Status { get; set; } = false;
    public string Message { get; set; } = string.Empty;
}
