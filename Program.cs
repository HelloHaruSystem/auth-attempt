using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MuAuthApp.Data;
using System.Text;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
//------------------------------------------------------------Swagger------------------------------------------------------------\\
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddSwaggerGen(c => 
{
    // Add JWT bearer token support in swagger UI
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat ="JWT",
        Scheme = "bearer",
        In = ParameterLocation.Header,
        Description = "Please enter JWT with Bearer into field"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
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
            new string[] {}
        }
    });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

//-----------------------------------------------------------Database-------------------------------------------------------------\\
// add db context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

//-------------------------------------------------------Identity service---------------------------------------------------------\\
// configure Identity service used for auth
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

//-----------------------------------------------------Debug Authentication?-------------------------------------------------------\\
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        // forces the token handler to handle the token
        options.MapInboundClaims = false;
    });

//--------------------------------------------------------Authentication----------------------------------------------------------\\
// Read JSON WEB Token(JWT) settings from appsettings.json
var jwtSettings = builder.Configuration.GetSection("JwtSettings");

// Configure Authentication with JWT Bearer
builder.Services.AddAuthentication(options => 
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options => 
    {
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var token = context.Request.Cookies["jwt"];
                if(!string.IsNullOrEmpty(token))
                {
                    context.Token = token;
                }
                return Task.CompletedTask;
            }
        };

        options.IncludeErrorDetails = true;
        // Token validation parameters
        options.TokenValidationParameters = new TokenValidationParameters
        {   
            

            // secret key specified in appsettings.json
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Secret"])),

            // the token issuer 
            ValidateIssuer = true,
            ValidIssuer = jwtSettings["Issuer"],

            // Audience
            ValidateAudience = true,
            ValidAudience = jwtSettings["Audience"],

            // expiration time (from appsettings.json)
            RequireExpirationTime = true,
            ValidateLifetime = true,
        };
    });

// add auth services
builder.Services.AddAuthorization();

//--------------------------------------------------------add Controllers-------------------------------------------------------\\
builder.Services.AddControllers();

//--------------------------------------------------CORS for local development---------------------------------------------------\\
// CORS = Cross-Origin Resource Sharing
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend",
    policy =>
    {
        policy.WithOrigins("http://localhost:5500")
            .AllowCredentials()
            .WithHeaders("Authorization", "Content-Type")
            .WithMethods("GET", "POST", "PUT", "DELETE", "OPTIONS");
    });
});

//-------------------------------------------------------------Build-------------------------------------------------------------\\
var app = builder.Build();

//------------------------------------------------------------Use Cors-------------------------------------------------------------\\
app.UseCors("AllowFrontend");

//-----------------------------------------------------HTTP Request pipeline------------------------------------------------------\\
app.UseRouting(); 
app.UseAuthentication();
app.UseAuthorization();

//--------------------------------------------------------Sample mapping----------------------------------------------------------\\
app.MapGet("/", () => "Hello World");

//--------------------------------------------------------map controllers----------------------------------------------------------\\
app.MapControllers();

//--------------------------------------------------------If Development----------------------------------------------------------\\
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//------------------------------------------------------------Run App--------------------------------------------------------------\\
app.Run();