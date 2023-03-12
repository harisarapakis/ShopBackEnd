using System.Security.Cryptography;
using System.Text;

namespace Shop.Helpers

{
    public class PasswordHasher
    {
        public static string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                // Convert the password to a byte array
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                // Compute the hash value of the password
                byte[] hashBytes = sha256.ComputeHash(passwordBytes);
                // Convert the hash value to a hexadecimal string
                string hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                return hashString;
            }
        }

        public static bool VerifyPassword(string password, string hashedPassword)
            {
                using (var sha256 = SHA256.Create())
                {
                    // Convert the password to a byte array
                    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

                    // Compute the hash value of the password
                    byte[] hashBytes = sha256.ComputeHash(passwordBytes);

                    // Convert the hash value to a hexadecimal string
                    string hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                    // Compare the hash string to the stored hashed password
                    return hashString == hashedPassword;
                }
            }

}
}
