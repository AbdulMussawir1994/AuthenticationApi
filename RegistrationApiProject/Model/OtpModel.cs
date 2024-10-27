using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace RegistrationApiProject.Model
{
    [Table("OtpModel", Schema = "dbo")]
    public class OtpModel
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [ForeignKey(nameof(User))]
        public string UserId { get; set; } 
        public string OtpCode { get; set; }
        public string OtpName { get; set; }  = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; } 

        public virtual ApplicationUser User { get; set; }
    }
}
