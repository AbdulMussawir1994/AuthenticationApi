using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace RegistrationApiProject.Helpers
{
    public class GlobalExceptionMiddleWare : IMiddleware
    {
        private readonly ILogger<GlobalExceptionMiddleWare> _logger;
        private readonly bool _isDevelopment;

        public GlobalExceptionMiddleWare(ILogger<GlobalExceptionMiddleWare> logger, IWebHostEnvironment env)
        {
            _logger = logger;
            _isDevelopment = env.IsDevelopment();
        }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            try
            {
                await next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            int statusCode = exception switch
            {
                ArgumentNullException => (int)HttpStatusCode.BadRequest,
                UnauthorizedAccessException => (int)HttpStatusCode.Unauthorized,
                _ => (int)HttpStatusCode.InternalServerError
            };

            var problemDetails = new ProblemDetails
            {
                Status = statusCode,
                Type = $"https://httpstatuses.com/{statusCode}",
                Title = GetTitleForStatusCode(statusCode),
                Detail = _isDevelopment ? exception.StackTrace : "An internal server error occurred. Please contact support."
            };

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = statusCode;

            _logger.LogError(exception, "Unhandled exception occurred at {Path}", context.Request.Path);

            await context.Response.WriteAsJsonAsync(problemDetails);
        }

        private static string GetTitleForStatusCode(int statusCode) => statusCode switch
        {
            (int)HttpStatusCode.BadRequest => "Bad Request",
            (int)HttpStatusCode.Unauthorized => "Unauthorized",
            (int)HttpStatusCode.InternalServerError => "An unexpected error occurred!",
            _ => "Error"
        };
    }
}
