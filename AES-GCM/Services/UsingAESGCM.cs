using System.Security.Cryptography;
using System.Text;

namespace Services;

public static class UsingAESGCM
{
    public static (byte[] cipher, byte[] nonce, byte[] tag) Encrypt
    (string text, byte[] key)
    {
        using (var aes = new AesGcm(key))
        {
            //nonce = Initialization Vector IV
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            RandomNumberGenerator.Fill(nonce);
            var plainTextBytes = Encoding.UTF8.GetBytes(text);
            var cipher = new byte[plainTextBytes.Length];
            //Authentication tag
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];

            aes.Encrypt(nonce, plainTextBytes, cipher, tag);

            return (cipher, nonce, tag);
        }
    }

    public static string Decrypt(byte[] cipher, byte[] key, byte[] nonce, byte[] tag)
    {
        using (var aes = new AesGcm(key))
        {
            var plainTextBytes = new byte[cipher.Length];
            aes.Decrypt(nonce, cipher, tag, plainTextBytes);
            return Encoding.UTF8.GetString(plainTextBytes);
        }
    }
}