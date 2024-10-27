using Twilio.Types;
using Twilio;
using Twilio.Rest.Api.V2010.Account;

namespace RegistrationApiProject.RepositoryLayer.SMSLayers;

public class SmsService
{
    private readonly string _accountSid;
    private readonly string _authToken;
    private readonly string _fromPhoneNumber;

    public SmsService(IConfiguration configuration)
    {
        _accountSid = configuration["Twilio:AccountSid"];
        _authToken = configuration["Twilio:AuthToken"];
        _fromPhoneNumber = configuration["Twilio:FromPhoneNumber"];

        TwilioClient.Init(_accountSid, _authToken);
    }

    public async Task SendMobileVerificationCodeAsync(string mobileNumber, string code)
    {
        try
        {
            var message = await MessageResource.CreateAsync(
                body: $"Your cell number verification code is: {code}",
                from: new PhoneNumber(_fromPhoneNumber),
                to: new PhoneNumber(mobileNumber)
            );

            if (message.Status == MessageResource.StatusEnum.Failed)
            {
                throw new Exception($"Failed to send SMS verification code. Error: {message.ErrorMessage}");
            }
        }
        catch (Exception ex)
        {
            throw new Exception("An error occurred while sending the SMS verification code.", ex);
        }
    }
}
