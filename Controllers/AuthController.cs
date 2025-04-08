using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MuAuthApp.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MuAuthApp.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        // login endpoint as well as generate JSON web token (JWT)
        // this is a POST request where we accept a username and password in the request body
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var token = GenerateJwtToken(user);
                System.Console.WriteLine($"Generated token : {token}");
                return Ok(new { Token = token });
            }

            return Unauthorized();
        }

        [HttpGet("debug-auth")]
        public IActionResult DebugAuth()
        {
            var authHeader = HttpContext.Request.Headers["Authorization"].ToString();

            return Ok(new
            {
                HasAuthHeader = !string.IsNullOrEmpty(authHeader),
                AuthHeaderValue = authHeader,
                AuthScheme = authHeader?.Split(' ')?.FirstOrDefault(),
                TokenPresent = authHeader?.Contains("Bearer") == true,
                TokenValue = authHeader?.Replace("Bearer ", "")
            });
        }

        // [Authorize] makes it so only authenticated users can access this end points
        [HttpGet("profile")]
        [Authorize] 
        public IActionResult GetProfile()
        {
            // Debug the authorization header
            var authHeader = Request.Headers["Authorization"].ToString();
            Console.WriteLine($"Auth Header: {authHeader}");

            var username = User.Identity.Name;
            Console.WriteLine($"Username from token: {username}");

            return Ok(new { Username = username });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                // check if both username and email already exists
                var existingUser = await _userManager.FindByNameAsync(model.UserName);
                if (existingUser != null)
                {
                    return BadRequest("Username already exists.");
                }

                var existingEmail = await _userManager.FindByEmailAsync(model.Email);
                if (existingEmail != null)
                {
                    return BadRequest("Email already exists.");
                }

                // else crete new identify user
                var user = new IdentityUser
                {
                    UserName = model.UserName,
                    Email = model.Email
                };
                
                // then create a user with the provided password
                var result = await _userManager.CreateAsync(user, model.Password);

                // if successful generate a JWT token 
                if (result.Succeeded)
                {
                    var token = GenerateJwtToken(user);
                    return Ok(new { Token = token });
                }

                return BadRequest(result.Errors);
            }

            return BadRequest("Invalid data.");
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            List<Claim> claims  =
            [
                // Sub is the subject of the token (the username of the authenticated user)
                // Jti is a unique identifier for the token aka GUID
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, user.UserName)
            ];
            
            // we use the secret key from appsettins to sing the jwt
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Secret"]));
            Console.WriteLine(jwtSettings["Secret"]);
            Console.WriteLine(key.ToString());
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(jwtSettings["ExpireMinutes"])),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}