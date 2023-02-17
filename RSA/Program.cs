using System.Security.Cryptography;
using System.Text;

var keys = RSA.Create(3072);

Console.WriteLine(keys.ExportRSAPublicKeyPem());
Console.WriteLine(keys.ExportRSAPrivateKeyPem());

byte[] plain = Encoding.UTF8.GetBytes("Some text to encrypt");

Console.WriteLine("Signature:");
var signature = keys.SignData(plain,
                            HashAlgorithmName.SHA256,
                            RSASignaturePadding.Pss);

Console.WriteLine(Convert.ToBase64String(signature));

Console.WriteLine("Cipher:");
var cipher = keys.Encrypt(plain, RSAEncryptionPadding.OaepSHA256);
Console.WriteLine(Convert.ToBase64String(cipher));

Console.WriteLine("Plain:");
Console.WriteLine(Encoding.UTF8.GetString
(keys.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256)));