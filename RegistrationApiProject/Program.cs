using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.OpenApi.Models;
using System.Reflection;
using System.Text.Json.Serialization;
using System.Text.Json;
using NLog;
using Serilog;
using RegistrationApiProject.Helpers;
using RegistrationApiProject.DatabaseContext;
using Microsoft.EntityFrameworkCore;
using RegistrationApiProject.Model;
using Mapster;
using Microsoft.AspNetCore.Mvc.Versioning;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NLog.Web;
using RegistrationApiProject.RepositoryLayer.AuthLayers;
using RegistrationApiProject.RepositoryLayer.EmailLayers;
using RegistrationApiProject.RepositoryLayer.OtpLayers;
using RegistrationApiProject.ViewModel;
using RegistrationApiProject.RepositoryLayer.SMSLayers;


var logger = LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("init main");

try
{
    Log.Information("Application starting...");

    var builder = WebApplication.CreateBuilder(args);
    ConfigurationManager Configuration = builder.Configuration;
    IWebHostEnvironment env = builder.Environment;

    builder.Host.SerilogConfiguration();

    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    if (string.IsNullOrEmpty(connectionString))
    {
        throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
    }

    builder.Services.AddDbContext<DbContextClass>(options =>
        options.UseSqlServer(connectionString, sqlOptions =>
        {
            sqlOptions.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(10),
                errorNumbersToAdd: null);
        }));


    builder.Services.AddScoped<IAuthenticationLayer, AuthenticationLayer>();
    builder.Services.AddTransient<IOTPService, OTPService>();
    builder.Services.AddTransient<EmailService>();
    builder.Services.AddTransient<SmsService>();
    builder.Services.Configure<EmailServiceSettingsViewModel>(builder.Configuration.GetSection("EmailServiceSettings"));

    builder.Services.AddResponseCaching();
    builder.Services.AddHttpClient();
    builder.Services.AddHttpContextAccessor();
 //   builder.Services.AddSingleton<IUrlHelperFactory, UrlHelperFactory>();

    builder.Services.AddControllers(options =>
    {
    }).AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.WriteIndented = true;
        options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.IgnoreReadOnlyFields = true;
    });

    builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+/ ";
        options.User.RequireUniqueEmail = false;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = false;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequireUppercase = false;
        options.Password.RequiredLength = 6;

    }).AddRoles<IdentityRole>()
                    .AddEntityFrameworkStores<DbContextClass>()
                    .AddUserStore<CustomUserStore>()
                    .AddDefaultTokenProviders();

    builder.Services.AddTransient<GlobalExceptionMiddleWare>();

    TypeAdapterConfig.GlobalSettings.Scan(Assembly.GetExecutingAssembly());
    builder.Services.AddSingleton(new MapsterProfile());

    builder.Services.AddApiVersioning(o =>
    {
        o.AssumeDefaultVersionWhenUnspecified = false;
        o.ApiVersionReader = new UrlSegmentApiVersionReader();
        o.ReportApiVersions = true;
    });

    builder.Services.AddCors(cors => cors.AddPolicy("AllowApi", builder =>
    {
        builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    }));

    builder.Services.AddRateLimiter(rateLimiterOptions =>
    {
        rateLimiterOptions.AddTokenBucketLimiter("token", options =>
        {
            options.TokenLimit = 100;
            options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
            options.QueueLimit = 5;
            options.ReplenishmentPeriod = TimeSpan.FromSeconds(10);
            options.TokensPerPeriod = 20;
            options.AutoReplenishment = true;
        });
    });

    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("RequireAdminClaims", policy =>
        {
            policy.RequireClaim("Admin", "Get Manager")
                      .RequireRole("Admin");
        });
    });

    builder.Services.AddAuthentication(option =>
    {
        option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        option.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    }).AddJwtBearer(options =>
    {
        var key = Encoding.ASCII.GetBytes(Configuration["JWTKey:Secret"]);

        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateAudience = true,
            ValidIssuer = Configuration["JWTKey:ValidIssuer"],
            ValidAudience = Configuration["JWTKey:ValidAudience"],
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero,
        };
    });


    builder.Services.AddSwaggerGen(options =>
    {
        options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
        {
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey,
            Scheme = "Bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: Bearer eyJhbGciOiJIUzI1",
        });

        options.AddSecurityRequirement(new OpenApiSecurityRequirement
     {
           {
                 new OpenApiSecurityScheme
                  {
                       Reference = new OpenApiReference
                        {
                             Type = ReferenceType.SecurityScheme,
                             Id = "Bearer"
                        }
                  },
                  new string[]{}
           }
     });
    });

    builder.Services.AddEndpointsApiExplorer();

    var app = builder.Build();

    app.UseMiddleware<GlobalExceptionMiddleWare>();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();
    app.UseResponseCaching();
    app.UseCors("AllowApi");
    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();
    app.UseRateLimiter();

    app.MapControllers();

    app.Run();

}
catch (Exception exception)
{
    logger.Error(exception.Message, $"Stopped program because of exception - {DateTime.Now}");
    throw;
}
finally
{
    // Ensure to flush and stop internal timers/threads before application-exit (Avoid segmentation fault on Linux)
    NLog.LogManager.Shutdown();
}
