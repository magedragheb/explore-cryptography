using System.Security.Cryptography;
using NSec.Cryptography;
using System.Text;

var Algorithm = AeadAlgorithm.XChaCha20Poly1305;

//https://nsec.rocks/docs/api/nsec.cryptography.keyexportpolicies
//default policy is none, which protects the key from reading
var param = new KeyCreationParameters
{ ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving };

using var key = new Key(Algorithm, param);

Console.WriteLine($"Key: {Convert.ToBase64String(key.Export(KeyBlobFormat.NSecSymmetricKey))}");

var nonce = new byte[Algorithm.NonceSize];
RandomNumberGenerator.Fill(nonce);
Console.WriteLine($"Nonce: {Convert.ToBase64String(nonce)}");

var tag = new byte[Algorithm.TagSize];
RandomNumberGenerator.Fill(tag);
Console.WriteLine($"Tag: {Convert.ToBase64String(tag)}");

var message = Encoding.UTF8.GetBytes("sample text to encrypt with XChaCha20Poly1305 with key length 256!");
var cipher = XChaCha20Poly1305.XChaCha20Poly1305.Encrypt(key, nonce, tag, message);
var decoded = XChaCha20Poly1305.XChaCha20Poly1305.Decrypt(key, nonce, tag, cipher);

Console.WriteLine($"Cipher: {Convert.ToBase64String(cipher)}");
Console.WriteLine(decoded != null ? $"Decoded: {Encoding.UTF8.GetString(decoded)}" : "-");