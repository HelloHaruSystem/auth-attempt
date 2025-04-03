using System.ComponentModel.DataAnnotations;

namespace MuAuthApp.Models
{
    public class LoginModel
    {
        [Required]
        [StringLength(100, MinimumLength = 3)]
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}