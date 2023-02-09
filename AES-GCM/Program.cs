using System.Security.Cryptography;
using Services;

var mytext = "sample text to encrypt with AES-GCM with key length 256!";

Console.WriteLine($"Plain: {mytext}");

var key = new byte[32];
RandomNumberGenerator.Fill(key);

Console.WriteLine($"Key: {Convert.ToBase64String(key)}");

var (cipher, nonce, tag) = UsingAESGCM.Encrypt(mytext, key);

Console.WriteLine($"Cipher: {Convert.ToBase64String(cipher)}");
Console.WriteLine($"Nonce: {Convert.ToBase64String(nonce)}");
Console.WriteLine($"Tag: {Convert.ToBase64String(tag)}");

var decoded = UsingAESGCM.Decrypt(cipher, key, nonce, tag);

Console.WriteLine($"Decode: {decoded}");
