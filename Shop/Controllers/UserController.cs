using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Shop.Database;
using Shop.Helpers;
using Shop.Model.Models;
using Shop.Model.Models.Dto;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Shop.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : Controller
    {
        private readonly MyDbContext _myDbContext;
        public UserController(MyDbContext myDbContext)
        {
            _myDbContext = myDbContext;
        }
        [HttpPost("authendicated")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();
            
            var user = await _myDbContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);
            if (user == null)
                return NotFound(new {Message = "User Not Found!"});
            if(!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
                {
                return BadRequest(new { Message = "Password is Incorect" });
            }
            // Generate a new JWT token for the authenticated user
            var token = GenerateJwtToken(user);

            // Update the user's token in the database
            user.Token = token;
            var newAccessToken = user.Token;
            var newRefreshToken = RefreshToken();
            userObj.RefreshToken = newRefreshToken;
            userObj.RefreshTokenExpiryTime = DateTime.Now.AddDays(5);
            await _myDbContext.SaveChangesAsync();

            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
            });

        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();
            if (await CheckUsernameExists(userObj.UserName))
                return BadRequest(new { Message = "Username already exists" });
            if (await CheckEmailExists(userObj.Email))
                return BadRequest(new { Message = "Email already exists" });

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = GenerateJwtToken(userObj);
            await _myDbContext.Users.AddAsync(userObj);
            await _myDbContext.SaveChangesAsync();

            return Ok(new
            {
                Token = userObj.Token,
                Message = "Login Success!"
            });
        }
        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _myDbContext.Users.ToListAsync());
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if (tokenApiDto == null)
                return BadRequest("Invalid Client");
            string accessToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;
            var principal = GetPrincipalFromExpiresToken(accessToken);
            var username = principal.Identity.Name;
            var user = await _myDbContext.Users.FirstOrDefaultAsync(u => u.UserName == username);
            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                return BadRequest("Invalid Request");
            var newAccessToken = GenerateJwtToken(user);
            var newRefreshToken = RefreshToken();
            user.RefreshToken = newRefreshToken;
            await _myDbContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
            });
        }
        private async Task<bool> CheckUsernameExists(string userName)
        {
            return await _myDbContext.Users.AnyAsync<User>(x => x.UserName == userName);
        }
        private async Task<bool> CheckEmailExists(string email)
        {
            return await _myDbContext.Users.AnyAsync<User>(x => x.Email == email);
        }
        private string GenerateJwtToken(User user)
        {
            // Create a security key using the secret key
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ThisismysecretCode................."));

            // Create the signing credentials
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            var idenitty = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.UserName}"),
            });

            // Create the token descriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = signingCredentials,
                Subject = idenitty
            };

            // Create the token handler
            var tokenHandler = new JwtSecurityTokenHandler();

            // Create the token using the token handler
            var token = tokenHandler.CreateToken(tokenDescriptor);

            // Return the serialized token
            return tokenHandler.WriteToken(token);
        }
        private string RefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);

            var tokenInUser = _myDbContext.Users
                .Any(x => x.RefreshToken == refreshToken);

            if (tokenInUser)
            {
                return RefreshToken();
            }
            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipalFromExpiresToken(string token)
        {
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ThisismysecretCode................."));

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                ValidateLifetime = false,
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;    
            if(jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase))
                 throw new SecurityTokenException("This is Invalid Token");

            return principal;


        }
    }
}
