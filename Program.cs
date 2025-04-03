using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MuAuthApp.Data;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
//------------------------------------------------------------Swagger------------------------------------------------------------\\
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

//-----------------------------------------------------------Database-------------------------------------------------------------\\
// 1: add db context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

//-------------------------------------------------------Identity service---------------------------------------------------------\\
// 2: configure Identity service used for auth
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

//--------------------------------------------------------Authentication----------------------------------------------------------\\
// 3: Read JSON WEB Token(JWT) settings from appsettings.json
var jwtSettings = builder.Configuration.GetSection("JwtSettings");

// 4: Configure Authentication with JWT Bearer
builder.Services.AddAuthentication(options => 
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options => 
    {
        // 4: Token validation parameters
        options.TokenValidationParameters = new TokenValidationParameters
        {   
            // secret key specified in appsettings.json
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["secret"])),

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
// builder.Services.AddControllers();

//-------------------------------------------------------------Build-------------------------------------------------------------\\
var app = builder.Build();

//-----------------------------------------------------HTTP Request pipeline------------------------------------------------------\\
app.UseAuthentication();
app.UseAuthorization();

//--------------------------------------------------------If Development----------------------------------------------------------\\
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//--------------------------------------------------------Sample mapping----------------------------------------------------------\\
app.MapGet("/", () => "Hello World");

//--------------------------------------------------------map controllers----------------------------------------------------------\\
// app.MapControllers();

//------------------------------------------------------------Run App--------------------------------------------------------------\\
app.Run();