using Amazon.SimpleEmail;
using Amazon.SimpleEmail.Model;
using Microsoft.Extensions.Options;
using RegistrationApiProject.ViewModel;
using System.Net;

namespace RegistrationApiProject.RepositoryLayer.EmailLayers;

public class EmailService
{
    private readonly EmailServiceSettingsViewModel _settings;
    private readonly IAmazonSimpleEmailService _sesClient;

    public EmailService(IOptions<EmailServiceSettingsViewModel> settings)
    {
        _settings = settings.Value;
        _sesClient = new AmazonSimpleEmailServiceClient(
            _settings.Key,
            _settings.Secret,
            Amazon.RegionEndpoint.GetBySystemName(_settings.Region)
        );
    }

    public async Task SendOtpAsync(string toEmail, string otpCode)
    {
        var subject = "Email Verification OTP";
        var body = $"<p>Your OTP for email verification is: <strong>{otpCode}</strong></p>";

        var sendRequest = new SendEmailRequest
        {
            Source = _settings.From,
            Destination = new Destination
            {
                ToAddresses = new List<string> { toEmail }
            },
            Message = new Message
            {
                Subject = new Content(subject),
                Body = new Body
                {
                    Html = new Content
                    {
                        Charset = "UTF-8",
                        Data = body
                    }
                }
            }
        };

        try
        {
            var response = await _sesClient.SendEmailAsync(sendRequest);

            if (response.HttpStatusCode != HttpStatusCode.OK)
            {
                throw new Exception("Failed to send OTP email.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception caught in SendOtpAsync(): {ex}");
            throw;
        }
    }
}
